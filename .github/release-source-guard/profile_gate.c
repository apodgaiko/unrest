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
    PyObject *events[7];
    PyObject *keys[6];
} Gate;

enum { OPERATIONS, OPERATION_SOURCES, COMPOSITION, SNAPSHOT, GUARD, CODES };
static const char *key_names[6] = {
    "operations", "operation_profile_sources", "isolated_composition",
    "primary_snapshot_observer", "guard", "codes"
};
static const char *event_names[7] = {
    [PyTrace_CALL] = "call", [PyTrace_RETURN] = "return", [PyTrace_C_CALL] = "c_call",
    [PyTrace_C_EXCEPTION] = "c_exception", [PyTrace_C_RETURN] = "c_return"
};

static int gate_traverse(Gate *self, visitproc visit, void *arg) {
    Py_VISIT(self->callback);
    Py_VISIT(self->state);
    Py_VISIT(self->sources);
    Py_VISIT(self->runner_suffix);
    for (int i = 0; i < 7; i++) Py_VISIT(self->events[i]);
    for (int i = 0; i < 6; i++) Py_VISIT(self->keys[i]);
    return 0;
}

static int gate_clear(Gate *self) {
    Py_CLEAR(self->callback);
    Py_CLEAR(self->state);
    Py_CLEAR(self->sources);
    Py_CLEAR(self->runner_suffix);
    for (int i = 0; i < 7; i++) Py_CLEAR(self->events[i]);
    for (int i = 0; i < 6; i++) Py_CLEAR(self->keys[i]);
    return 0;
}

static void gate_dealloc(Gate *self) {
    PyObject_GC_UnTrack(self);
    gate_clear(self);
    PyObject_GC_Del(self);
}

static int gate_profile(PyObject *object, PyFrameObject *frame, int event, PyObject *value);

static int gate_selected(Gate *self, PyFrameObject *frame, PyObject *event) {
    PyObject *operations = PyDict_GetItem(self->state, self->keys[OPERATIONS]);
    PyObject *operation_sources = PyDict_GetItem(self->state, self->keys[OPERATION_SOURCES]);
    if (operations && operations != Py_None && (!operation_sources || !PyFrozenSet_Check(operation_sources)))
        return 1;
    PyCodeObject *code = PyFrame_GetCode(frame);
    if (!code) return -1;
    int selected = PySet_Contains(self->sources, code->co_filename);
    if (selected == 0 && PyUnicode_CompareWithASCIIString(code->co_name, "call_and_report") == 0) {
        selected = PyUnicode_Tailmatch(code->co_filename, self->runner_suffix, 0, PY_SSIZE_T_MAX, 1);
    }
    if (selected == 0) {
        PyObject *composition = PyDict_GetItem(self->state, self->keys[COMPOSITION]);
        if (!composition) {
            Py_DECREF(code);
            return 1;
        }
        PyObject *codes = PyObject_GetAttr(composition, self->keys[CODES]);
        if (!codes) {
            Py_DECREF(code);
            return -1;
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
        PyObject *observer = PyDict_GetItem(self->state, self->keys[SNAPSHOT]);
        PyObject *guard = PyDict_GetItem(self->state, self->keys[GUARD]);
        if (observer && PyCallable_Check(observer) && guard && PyUnicode_Check(guard))
            selected = PyObject_RichCompareBool(code->co_filename, guard, Py_EQ);
    }
    Py_DECREF(code);
    if (selected < 0 || PyErr_Occurred()) return -1;
    return selected;
}

static PyObject *gate_forward(Gate *self, PyFrameObject *frame, PyObject *event, PyObject *value) {
    int selected = gate_selected(self, frame, event);
    if (selected < 0) return NULL;
    if (!selected) Py_RETURN_NONE;
    return PyObject_CallFunctionObjArgs(self->callback, (PyObject *)frame, event, value, NULL);
}

static int gate_failed(void) {
    /* Match sys.setprofile's trampoline: a failed callback is removed before
     * unwinding can emit another return event. Keep the original exception. */
    PyObject *error = PyErr_GetRaisedException();
    if (!error) {
        PyErr_SetString(PyExc_RuntimeError, "native profile callback failed without an exception");
        error = PyErr_GetRaisedException();
    }
    PyEval_SetProfile(NULL, NULL);
    PyErr_SetRaisedException(error);
    return -1;
}

static int gate_profile(PyObject *object, PyFrameObject *frame, int what, PyObject *value) {
    /* PyEval's native hook keeps this exact Gate as c_profileobj, so
     * sys.getprofile(), restoration and thread inheritance keep their identity.
     * Ignored events no longer allocate a Python argument tuple or call Gate.
     * The unchanged predicate and selected-event callback still see every event. */
    Gate *self = (Gate *)object;
    if (what < 0 || what >= 7 || !self->events[what]) {
        PyErr_SetString(PyExc_RuntimeError, "unsupported native profile event");
        return gate_failed();
    }
    PyObject *event = Py_NewRef(self->events[what]);
    PyObject *result = gate_forward((Gate *)object, frame, event, value ? value : Py_None);
    Py_DECREF(event);
    if (!result) return gate_failed();
    Py_DECREF(result);
    return 0;
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
    PyThreadState *thread = PyThreadState_Get();
    /* Only promote a Gate actually installed by sys.setprofile on this thread.
     * A direct call cannot install or replace a different profile observer. */
    if (thread->c_profileobj == object && thread->c_profilefunc != gate_profile) {
        PyEval_SetProfile(gate_profile, object);
        if (PyErr_Occurred()) return NULL;
    }
    return gate_forward(self, (PyFrameObject *)frame, event, value);
}

static PyObject *uses_native_profile(PyObject *module, PyObject *object) {
    (void)module;
    PyThreadState *thread = PyThreadState_Get();
    return PyBool_FromLong(thread->c_profilefunc == gate_profile && thread->c_profileobj == object);
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
    for (int i = 0; i < 7; i++) gate->events[i] = NULL;
    for (int i = 0; i < 6; i++) gate->keys[i] = NULL;
    gate->callback = Py_NewRef(callback);
    gate->state = Py_NewRef(state);
    gate->sources = Py_NewRef(sources);
    gate->runner_suffix = PyUnicode_FromString("/_pytest/runner.py");
    if (!gate->runner_suffix) {
        Py_DECREF(gate);
        return NULL;
    }
    for (int i = 0; i < 7; i++) {
        if (event_names[i]) {
            gate->events[i] = PyUnicode_InternFromString(event_names[i]);
            if (!gate->events[i]) { Py_DECREF(gate); return NULL; }
        }
    }
    for (int i = 0; i < 6; i++) {
        gate->keys[i] = PyUnicode_InternFromString(key_names[i]);
        if (!gate->keys[i]) { Py_DECREF(gate); return NULL; }
    }
    PyObject_GC_Track(gate);
    return (PyObject *)gate;
}

static PyMethodDef methods[] = {
    {"make", make_gate, METH_VARARGS, "Forward selected source events and the bound guard constructor return."},
    {"uses_native_profile", uses_native_profile, METH_O, "Whether this Gate is the current thread's native profile observer."},
    {NULL, NULL, 0, NULL}
};
static struct PyModuleDef definition = {
    PyModuleDef_HEAD_INIT, "profile_gate", NULL, -1, methods, NULL, NULL, NULL, NULL
};
PyMODINIT_FUNC PyInit_profile_gate(void) {
    if (PyType_Ready(&GateType) < 0) return NULL;
    return PyModule_Create(&definition);
}
