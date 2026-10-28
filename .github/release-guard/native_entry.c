/* Register the guard before Python initialization or a source body can run. */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#ifndef GUARD_BOOTSTRAP
#error immutable bootstrap path required
#endif
#ifndef GUARD_BOOTSTRAP_SHA256
#error immutable bootstrap byte pin required
#endif
#ifndef GUARD_PROFILES
#error observer-owned profile directory required
#endif
#ifndef GUARD_CONTROL_SOCKET
#error fixed observer channel required
#endif
static int entering = 0, entered = 0, poisoned = 0;
static _Thread_local int checking = 0;
static PyObject *policy = NULL;
static int forbidden(const char *event) {
    return !strcmp(event,"subprocess.Popen") || !strcmp(event,"os.exec") ||
        !strcmp(event,"os.posix_spawn") || !strcmp(event,"os.system") ||
        !strcmp(event,"os.fork") || !strcmp(event,"os.forkpty") ||
        !strcmp(event,"socket.bind") || !strcmp(event,"socket.connect") ||
        !strcmp(event,"socket.sendto") || !strcmp(event,"socket.sendmsg") ||
        !strcmp(event,"socket.getaddrinfo") || !strcmp(event,"socket.getnameinfo") ||
        !strcmp(event,"socket.gethostbyname") || !strcmp(event,"socket.gethostbyaddr") ||
        !strcmp(event,"sys.setprofile") || !strcmp(event,"sys.settrace");
}
static int guard_audit(const char *event, PyObject *args, void *unused) {
    (void)unused;
    if (entering || checking) return 0;
    if (entered && !strcmp(event,"socket.connect") && PyTuple_Check(args) &&
        PyTuple_GET_SIZE(args) == 2 && PyUnicode_Check(PyTuple_GET_ITEM(args,1)) &&
        PyUnicode_CompareWithASCIIString(PyTuple_GET_ITEM(args,1),GUARD_CONTROL_SOCKET) == 0)
        return 0;  /* Only the fixed protected observer channel, never a caller path. */
    int effect = forbidden(event) || !strcmp(event,"compile") || !strcmp(event,"exec") ||
        !strcmp(event,"os.kill") || !strcmp(event,"os.killpg") ||
        !strcmp(event,"socket.__new__") || !strcmp(event,"import");
    if (entered && policy != NULL && !Py_IsFinalizing() && effect) {
        checking = 1;
        PyObject *answer = PyObject_CallFunction(policy,"sO",event,args);
        checking = 0;
        if (answer != Py_True) {
            poisoned = 1;
            Py_XDECREF(answer);
            if (!PyErr_Occurred()) PyErr_SetString(PyExc_RuntimeError,"source policy refused effect");
            return -1;
        }
        Py_DECREF(answer);
        return 0;
    }
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
        PyObject *candidate = PyDict_GetItemString(globals,"POLICY");
        if (candidate != NULL) {
            if (!PyCallable_Check(candidate)) _exit(86);
            policy = Py_NewRef(candidate);
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
    /* Only the compiled, byte-identical console entry selects normal pytest.
       Kernel argv stays in the trace; normalized Python argv is bound separately. */
#ifdef GUARD_PYTEST
    if (!strcmp(argv[0],GUARD_PYTEST)) {
        char **normalized = calloc((size_t)argc + 5, sizeof(char *));
        if (normalized == NULL) return 86;
        normalized[0]=argv[0]; normalized[1]="-I"; normalized[2]="-S";
        normalized[3]="-m"; normalized[4]="pytest";
        for (int i=1;i<argc;i++) normalized[i+4]=argv[i];
        int status=Py_BytesMain(argc+4,normalized);
        free(normalized);
        return poisoned ? 86 : status;
    }
#endif
    int status = Py_BytesMain(argc,argv);
    return poisoned ? 86 : status;
}
