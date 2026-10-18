/* Supported CPython audit registration before Py_BytesMain initializes Python. */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <string.h>
#include <unistd.h>

#ifndef ENTRY_SOURCE_SHA256
#error ENTRY_SOURCE_SHA256 must pin the immutable native entry source
#endif
static int entering = 0;
static int entered = 0;

static int source_audit(const char *event, PyObject *args, void *unused) {
    (void)unused;
    if (entering) return 0;
    if (!entered && (!strcmp(event, "subprocess.Popen") || !strcmp(event, "os.exec") ||
                     !strcmp(event, "os.posix_spawn") || !strcmp(event, "os.system") ||
                     !strcmp(event, "os.fork") || !strcmp(event, "os.forkpty") ||
                     !strcmp(event, "socket.connect") || !strcmp(event, "socket.bind"))) {
        /* This startup refusal cannot be caught by the not-yet-admitted body. */
        _exit(86);
    }
    if (!strcmp(event, "cpython.run_command") || !strcmp(event, "cpython.run_file") ||
        !strcmp(event, "cpython.run_module") || !strcmp(event, "cpython.run_stdin")) {
        if (entered) _exit(86);
        entering = 1;
        PyObject *module = PyModule_New("_finite_native_entry");
        if (module == NULL) _exit(86);
        PyObject *globals = PyModule_GetDict(module);
        PyObject *kind = PyUnicode_FromString(event);
        if (kind == NULL || PyDict_SetItemString(globals, "ENTRY_EVENT", kind) < 0 ||
            PyDict_SetItemString(globals, "ENTRY_ARGUMENTS", args) < 0) _exit(86);
        Py_DECREF(kind);
        const char *bootstrap =
            "import hashlib\n"
            "p='/guard/primary_entry.py'\n"
            "with open(p,'rb') as f: b=f.read()\n"
            "if hashlib.sha256(b).hexdigest() != '" ENTRY_SOURCE_SHA256 "': "
            "raise RuntimeError('native entry source drift')\n"
            "exec(compile(b,p,'exec'),globals())\n";
        PyObject *result = PyRun_StringFlags(bootstrap, Py_file_input, globals, globals, NULL);
        if (result == NULL) {
            PyErr_Print();
            _exit(86);
        }
        Py_DECREF(result);
        Py_DECREF(module);
        if (PySys_GetObject("_unrest_finite_source_audit") == NULL &&
            PySys_GetObject("_unrest_primary_source_bootstrap_consumed") == NULL) _exit(86);
        entered = 1;
        entering = 0;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (PySys_AddAuditHook(source_audit, NULL) < 0) return 86;
    return Py_BytesMain(argc, argv);
}
