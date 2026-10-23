#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <frameobject.h>

/* The Python observer already ignores these events. Keep that predicate here
 * so ignored dependency calls need no Python callback frame. Selected events,
 * including c_call/c_return, are forwarded with their original arguments.
 * The source observer also receives its bound guard constructor return. */
typedef struct {
    PyObject_HEAD
    PyObject *callback;
    PyObject *state;
    PyObject *sources;
    PyObject *runner_suffix;
    PyObject *keys[6];
} Gate;

static int gate_traverse(Gate *self, visitproc visit, void *arg) {
    Py_VISIT(self->callback);
    Py_VISIT(self->state);
    Py_VISIT(self->sources);
    Py_VISIT(self->runner_suffix);
    for (int i = 0; i < 6; i++) Py_VISIT(self->keys[i]);
    return 0;
}

static int gate_clear(Gate *self) {
    Py_CLEAR(self->callback);
    Py_CLEAR(self->state);
    Py_CLEAR(self->sources);
    Py_CLEAR(self->runner_suffix);
    for (int i = 0; i < 6; i++) Py_CLEAR(self->keys[i]);
    return 0;
}

static void gate_dealloc(Gate *self) {
    PyObject_GC_UnTrack(self);
    gate_clear(self);
    PyObject_GC_Del(self);
}

static PyObject *gate_call(PyObject *object, PyObject *args, PyObject *kwargs) {
    Gate *self = (Gate *)object;
    PyObject *frame, *event, *value;
    if ((kwargs && PyDict_Size(kwargs)) || !PyArg_ParseTuple(args, "OOO", &frame, &event, &value)) {
        if (!PyErr_Occurred()) PyErr_SetString(PyExc_TypeError, "profile arguments required");
        return NULL;
    }
    if (!PyFrame_Check(frame) || !PyUnicode_Check(event)) {
        PyErr_SetString(PyExc_TypeError, "profile frame and event required");
        return NULL;
    }
    PyObject *operations = PyDict_GetItem(self->state, self->keys[0]);
    PyObject *operation_sources = PyDict_GetItem(self->state, self->keys[1]);
    if (operations && operations != Py_None && (!operation_sources || !PyFrozenSet_Check(operation_sources)))
        return PyObject_CallObject(self->callback, args);
    PyCodeObject *code = PyFrame_GetCode((PyFrameObject *)frame);
    if (!code) return NULL;
    int selected = PySet_Contains(self->sources, code->co_filename);
    if (selected == 0 && PyUnicode_CompareWithASCIIString(code->co_name, "call_and_report") == 0) {
        selected = PyUnicode_Tailmatch(code->co_filename, self->runner_suffix, 0, PY_SSIZE_T_MAX, 1);
    }
    if (selected == 0) {
        PyObject *composition = PyDict_GetItem(self->state, self->keys[2]);
        if (!composition) {
            Py_DECREF(code);
            return PyObject_CallObject(self->callback, args);
        }
        PyObject *codes = PyObject_GetAttr(composition, self->keys[3]);
        if (!codes) {
            Py_DECREF(code);
            return NULL;
        }
        if (codes != Py_None) selected = PyObject_RichCompareBool((PyObject *)code, codes, Py_EQ);
        Py_DECREF(codes);
    }
    /* The source observer joins endpoint authentication at the existing guarded
     * constructor return. Forward that one event even though guard internals
     * are outside the ordinary source-file predicate. This observes no body
     * early and grants no execution, endpoint, or deadline authority. */
    if (selected == 0 && PyUnicode_CompareWithASCIIString(event, "return") == 0
            && PyUnicode_CompareWithASCIIString(code->co_name, "initialize_inner") == 0) {
        PyObject *observer = PyDict_GetItem(self->state, self->keys[4]);
        PyObject *guard = PyDict_GetItem(self->state, self->keys[5]);
        if (observer && PyCallable_Check(observer) && guard && PyUnicode_Check(guard))
            selected = PyObject_RichCompareBool(code->co_filename, guard, Py_EQ);
    }
    Py_DECREF(code);
    if (selected < 0 || PyErr_Occurred()) return NULL;
    if (!selected) Py_RETURN_NONE;
    return PyObject_CallObject(self->callback, args);
}

static PyTypeObject GateType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "profile_gate.Gate",
    .tp_basicsize = sizeof(Gate),
    .tp_dealloc = (destructor)gate_dealloc,
    .tp_call = gate_call,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
    .tp_traverse = (traverseproc)gate_traverse,
    .tp_clear = (inquiry)gate_clear,
};

static PyObject *make_gate(PyObject *module, PyObject *args) {
    (void)module;
    PyObject *callback, *state, *sources;
    if (!PyArg_ParseTuple(args, "OOO", &callback, &state, &sources)) return NULL;
    if (!PyCallable_Check(callback) || !PyDict_Check(state) || !PyAnySet_Check(sources)) {
        PyErr_SetString(PyExc_TypeError, "callback, state dictionary and source set required");
        return NULL;
    }
    Gate *gate = PyObject_GC_New(Gate, &GateType);
    if (!gate) return NULL;
    gate->callback = Py_NewRef(callback);
    gate->state = Py_NewRef(state);
    gate->sources = Py_NewRef(sources);
    for (int i = 0; i < 6; i++) gate->keys[i] = NULL;
    gate->runner_suffix = PyUnicode_FromString("/_pytest/runner.py");
    if (!gate->runner_suffix) {
        Py_DECREF(gate);
        return NULL;
    }
    const char *names[6] = {"operations", "operation_profile_sources", "isolated_composition", "codes", "primary_snapshot_observer", "guard"};
    for (int i = 0; i < 6; i++) {
        gate->keys[i] = PyUnicode_InternFromString(names[i]);
        if (!gate->keys[i]) {
            Py_DECREF(gate);
            return NULL;
        }
    }
    PyObject_GC_Track(gate);
    return (PyObject *)gate;
}

/* Iterate current trace rows without repeating no-effect producer callbacks.
 * Map membership is read again after every yield; no eligibility is retained. */
typedef struct {
    PyObject_HEAD
    PyObject *iterator;
    PyObject *owner;
    PyObject *keys[8];
} ProducerEvents;

static int producer_events_traverse(ProducerEvents *self, visitproc visit, void *arg) {
    Py_VISIT(self->iterator);
    Py_VISIT(self->owner);
    for (int i = 0; i < 8; i++) Py_VISIT(self->keys[i]);
    return 0;
}

static int producer_events_clear(ProducerEvents *self) {
    Py_CLEAR(self->iterator);
    Py_CLEAR(self->owner);
    for (int i = 0; i < 8; i++) Py_CLEAR(self->keys[i]);
    return 0;
}

static void producer_events_dealloc(ProducerEvents *self) {
    PyObject_GC_UnTrack(self);
    producer_events_clear(self);
    PyObject_GC_Del(self);
}

static int producer_events_plain_keys(PyObject *mapping, int integers) {
    Py_ssize_t position = 0;
    PyObject *key, *value;
    while (PyDict_Next(mapping, &position, &key, &value)) {
        if (integers ? !PyLong_CheckExact(key) : !PyUnicode_CheckExact(key)) return 0;
    }
    return 1;
}

static PyObject *producer_events_next(ProducerEvents *self) {
    if (!self->iterator || !self->owner) return NULL;
    PyObject *state = PyObject_GenericGetDict(self->owner, NULL);
    if (!state) {
        PyErr_Clear();
        return PyIter_Next(self->iterator);
    }
    PyObject *common = PyDict_CheckExact(state) && producer_events_plain_keys(state, 0) ? PyDict_GetItem(state, self->keys[0]) : NULL;
    PyObject *cache = common ? PyDict_GetItem(state, self->keys[2]) : NULL;
    PyObject *children = common ? PyDict_GetItem(state, self->keys[3]) : NULL;
    PyObject *uv = common ? PyDict_GetItem(state, self->keys[4]) : NULL;
    PyObject *primary = common && PyDict_CheckExact(common) && producer_events_plain_keys(common, 0)
        ? PyDict_GetItem(common, self->keys[1]) : NULL;
    if (!common || !PyDict_CheckExact(common) || !producer_events_plain_keys(common, 0)
            || !cache || !children || !PyDict_CheckExact(children)
            || !producer_events_plain_keys(children, 1)
            || !uv || !PyDict_CheckExact(uv) || !producer_events_plain_keys(uv, 1)
            || (primary && primary != Py_None && !PyBool_Check(primary) && !PyDict_CheckExact(primary))) {
        Py_DECREF(state);
        return PyIter_Next(self->iterator);
    }
    PyObject *row;
    while ((row = PyIter_Next(self->iterator))) {
        PyObject *kind = PyDict_CheckExact(row) && producer_events_plain_keys(row, 0)
            ? PyDict_GetItem(row, self->keys[5]) : NULL;
        int retain = 1;
        if (kind && PyUnicode_CheckExact(kind)) {
            if (PyUnicode_CompareWithASCIIString(kind, "original_parent_wait4") == 0) {
                PyObject *child = PyDict_GetItem(row, self->keys[6]);
                if (!primary || primary == Py_None || primary == Py_False
                        || (PyDict_CheckExact(primary) && PyDict_Size(primary) == 0)) {
                    retain = 0;
                } else if (child && PyLong_CheckExact(child)) {
                    retain = PyDict_Contains(children, child);
                }
            } else if (PyUnicode_CompareWithASCIIString(kind, "kernel_exit") == 0) {
                PyObject *pid = PyDict_GetItem(row, self->keys[7]);
                if (pid && PyLong_CheckExact(pid)) {
                    retain = PyDict_Contains(children, pid);
                    if (retain == 0) retain = PyDict_Contains(uv, pid);
                }
            } else {
                retain = 0;
            }
        }
        if (retain < 0 || PyErr_Occurred()) {
            Py_DECREF(row);
            Py_DECREF(state);
            return NULL;
        }
        if (retain) {
            Py_DECREF(state);
            return row;
        }
        Py_DECREF(row);
    }
    Py_DECREF(state);
    return NULL;
}

static PyTypeObject ProducerEventsType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "profile_gate.ProducerEvents",
    .tp_basicsize = sizeof(ProducerEvents),
    .tp_dealloc = (destructor)producer_events_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
    .tp_traverse = (traverseproc)producer_events_traverse,
    .tp_clear = (inquiry)producer_events_clear,
    .tp_iter = PyObject_SelfIter,
    .tp_iternext = (iternextfunc)producer_events_next,
};

static PyObject *producer_events(PyObject *module, PyObject *args) {
    (void)module;
    PyObject *rows, *owner;
    if (!PyArg_ParseTuple(args, "OO", &rows, &owner)) return NULL;
    if (!PyList_CheckExact(rows)) return Py_NewRef(rows);
    ProducerEvents *value = PyObject_GC_New(ProducerEvents, &ProducerEventsType);
    if (!value) return NULL;
    value->iterator = PyObject_GetIter(rows);
    value->owner = Py_NewRef(owner);
    for (int i = 0; i < 8; i++) value->keys[i] = NULL;
    if (!value->iterator) {
        Py_DECREF(value);
        return NULL;
    }
    const char *names[8] = {"common", "primary_producer", "cache_current", "children", "uv", "kind", "child", "pid"};
    for (int i = 0; i < 8; i++) {
        value->keys[i] = PyUnicode_InternFromString(names[i]);
        if (!value->keys[i]) {
            Py_DECREF(value);
            return NULL;
        }
    }
    PyObject_GC_Track(value);
    return (PyObject *)value;
}

static PyMethodDef methods[] = {
    {"producer_events", producer_events, METH_VARARGS, "Read current producer-relevant trace rows."},
    {"make", make_gate, METH_VARARGS, "Forward selected source events and the bound guard constructor return."},
    {NULL, NULL, 0, NULL}
};
static struct PyModuleDef definition = {
    PyModuleDef_HEAD_INIT, "profile_gate", NULL, -1, methods, NULL, NULL, NULL, NULL
};
PyMODINIT_FUNC PyInit_profile_gate(void) {
    if (PyType_Ready(&GateType) < 0) return NULL;
    if (PyType_Ready(&ProducerEventsType) < 0) return NULL;
    return PyModule_Create(&definition);
}
