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

static PyMethodDef methods[] = {
    {"make", make_gate, METH_VARARGS, "Forward selected source events and the bound guard constructor return."},
    {NULL, NULL, 0, NULL}
};
static struct PyModuleDef definition = {
    PyModuleDef_HEAD_INIT, "profile_gate", NULL, -1, methods, NULL, NULL, NULL, NULL
};
PyMODINIT_FUNC PyInit_profile_gate(void) {
    if (PyType_Ready(&GateType) < 0) return NULL;
    return PyModule_Create(&definition);
}
