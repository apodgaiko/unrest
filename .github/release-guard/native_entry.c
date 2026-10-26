/* Register the guard before Python initialization or a source body can run. */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <string.h>
#include <unistd.h>
#ifndef GUARD_BOOTSTRAP
#error immutable bootstrap path required
#endif
#ifndef GUARD_BOOTSTRAP_SHA256
#error immutable bootstrap byte pin required
#endif
#ifndef GUARD_PROFILES
#error observer-owned profile directory required
#endif
static int entering = 0, entered = 0, poisoned = 0;
static int forbidden(const char *event) {
    return !strcmp(event,"subprocess.Popen") || !strcmp(event,"os.exec") ||
        !strcmp(event,"os.posix_spawn") || !strcmp(event,"os.system") ||
        !strcmp(event,"os.fork") || !strcmp(event,"os.forkpty") ||
        !strcmp(event,"socket.bind") || !strcmp(event,"socket.connect") ||
        !strcmp(event,"socket.sendto") || !strcmp(event,"socket.sendmsg") ||
        !strcmp(event,"sys.setprofile") || !strcmp(event,"sys.settrace");
}
static int guard_audit(const char *event, PyObject *args, void *unused) {
    (void)unused;
    if (entering) return 0;
    if (forbidden(event)) {
        if (!entered) _exit(86);
        poisoned = 1;
        PyErr_SetString(PyExc_RuntimeError,"native control policy refused effect");
        return -1;
    }
    if (!strcmp(event,"cpython.run_command") || !strcmp(event,"cpython.run_file") ||
        !strcmp(event,"cpython.run_module") || !strcmp(event,"cpython.run_stdin")) {
        if (entered) _exit(86);
        entering = 1;
        PyObject *module = PyModule_New("_release_native_entry");
        if (module == NULL) _exit(86);
        PyObject *globals = PyModule_GetDict(module);
        PyObject *kind = PyUnicode_FromString(event);
        if (kind == NULL || PyDict_SetItemString(globals,"ENTRY_EVENT",kind) < 0 ||
            PyDict_SetItemString(globals,"ENTRY_ARGUMENTS",args) < 0) _exit(86);
        Py_DECREF(kind);
        const char *bootstrap =
            "import hashlib\n"
            "p=" GUARD_BOOTSTRAP "\n"
            "PROFILE_DIRECTORY=" GUARD_PROFILES "\n"
            "with open(p,'rb') as f: body=f.read()\n"
            "if hashlib.sha256(body).hexdigest() != '" GUARD_BOOTSTRAP_SHA256 "': "
            "raise RuntimeError('native bootstrap bytes changed')\n"
            "__file__=p\n"
            "exec(compile(body,p,'exec'),globals())\n";
        PyObject *result = PyRun_StringFlags(bootstrap,Py_file_input,globals,globals,NULL);
        if (result == NULL || PyDict_GetItemString(globals,"BODY_READY") != Py_True) {
            if (PyErr_Occurred()) PyErr_Print();
            _exit(86);
        }
        Py_DECREF(result);
        Py_DECREF(module);
        entered = 1;
        entering = 0;
    }
    return 0;
}
int main(int argc, char **argv) {
    if (PySys_AddAuditHook(guard_audit,NULL) < 0) return 86;
    /* Isolated UTF-8 startup must not rewrite the admitted environment by
       coercing LC_CTYPE. Keep the audit hook ahead of preinitialization. */
    PyPreConfig preconfig;
    PyPreConfig_InitIsolatedConfig(&preconfig);
    preconfig.utf8_mode = 1;
    PyStatus startup = Py_PreInitialize(&preconfig);
    if (PyStatus_Exception(startup)) Py_ExitStatusException(startup);
    int status = Py_BytesMain(argc,argv);
    return poisoned ? 86 : status;
}
