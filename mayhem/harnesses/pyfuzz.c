/*
 * libFuzzer entry for pygame: embeds CPython, imports the sanitized pygame extension modules
 * built by mayhem/build.sh, and hands each input to pgfuzz.fuzz_<PGFUZZ_TARGET>(bytes), a
 * Python driver that decodes the bytes into a short sequence of public pygame API calls.
 *
 * pygame has no C API of its own: its only interface is the Python one, so the fuzzed code
 * (src_c/ *.c) is reached exactly the way an application reaches it.  Python exceptions are
 * expected outcomes (ValueError, pygame.error, ...) and are swallowed by the driver; memory
 * errors and UB in the extension modules are caught by ASan/UBSan, which halt.
 *
 * Build-time defines:
 *   PGFUZZ_TARGET   driver name (draw, surface, ...)
 *   PGFUZZ_LIBDIR   directory holding the built `pygame` package
 *   PGFUZZ_PYDIR    directory holding pgfuzz.py
 *   PGFUZZ_INITTAB  (optional) header listing PGFUZZ_MOD(<name>) for each pygame extension module
 *                   linked INTO this executable.  build.sh compiles those modules' objects (with
 *                   SanCov) straight into the fuzz binary, renaming PyInit_<name> to
 *                   PyInit_pgfuzz_<name>, and they are registered here as built-in modules
 *                   `pygame.<name>`.  Python's BuiltinImporter runs before the path finder, so
 *                   `import pygame.draw` uses the linked-in code, not the dlopen'd .so: the fuzzed
 *                   code's coverage counters then live in the main executable, where Mayhem
 *                   measures edges.  Modules not listed still load from PGFUZZ_LIBDIR as usual.
 */
#include <Python.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef PGFUZZ_TARGET
#error "PGFUZZ_TARGET must be defined"
#endif

static PyObject *g_fuzz = NULL;

#ifdef PGFUZZ_INITTAB
#define PGFUZZ_MOD(m) extern PyObject *PyInit_pgfuzz_##m(void);
#include PGFUZZ_INITTAB
#undef PGFUZZ_MOD
#endif

static void die(const char *what)
{
    fprintf(stderr, "pyfuzz: %s\n", what);
    if (PyErr_Occurred())
        PyErr_Print();
    abort();
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    /* Headless SDL: no window, no audio device. */
    setenv("SDL_VIDEODRIVER", "dummy", 1);
    setenv("SDL_AUDIODRIVER", "dummy", 1);
    setenv("PYGAME_HIDE_SUPPORT_PROMPT", "1", 1);

#ifdef PGFUZZ_INITTAB
    /* Must precede interpreter initialisation. */
#define PGFUZZ_MOD(m)                                                  \
    if (PyImport_AppendInittab("pygame." #m, PyInit_pgfuzz_##m) != 0) \
        die("PyImport_AppendInittab(pygame." #m ") failed");
#include PGFUZZ_INITTAB
#undef PGFUZZ_MOD
#endif

    /* Route every Python allocation through malloc so ASan sees object/buffer bounds. */
    PyPreConfig pre;
    PyPreConfig_InitIsolatedConfig(&pre);
    pre.allocator = PYMEM_ALLOCATOR_MALLOC;
    if (PyStatus_Exception(Py_PreInitialize(&pre)))
        die("Py_PreInitialize failed");

    PyConfig cfg;
    PyConfig_InitIsolatedConfig(&cfg);
    cfg.write_bytecode = 0;      /* the image is read-only under Mayhem */
    cfg.use_hash_seed = 1;       /* deterministic dict/set order across runs */
    cfg.hash_seed = 0;
    cfg.site_import = 0;
    cfg.install_signal_handlers = 0; /* libFuzzer/ASan own the signals */
    PyStatus st = Py_InitializeFromConfig(&cfg);
    PyConfig_Clear(&cfg);
    if (PyStatus_Exception(st))
        die("Py_InitializeFromConfig failed");

    PyObject *sys_path = PySys_GetObject("path"); /* borrowed */
    PyObject *p1 = PyUnicode_FromString(PGFUZZ_LIBDIR);
    PyObject *p2 = PyUnicode_FromString(PGFUZZ_PYDIR);
    if (!sys_path || !p1 || !p2 || PyList_Insert(sys_path, 0, p1) || PyList_Insert(sys_path, 0, p2))
        die("cannot extend sys.path");
    Py_DECREF(p1);
    Py_DECREF(p2);

#ifdef PGFUZZ_INITTAB
    /* Every linked-in module must resolve to the built-in copy (no __file__), never to the .so. */
#define PGFUZZ_MOD(m)                                                        \
    {                                                                        \
        PyObject *bm = PyImport_ImportModule("pygame." #m);                 \
        if (!bm)                                                             \
            die("cannot import pygame." #m);                                \
        if (PyObject_HasAttrString(bm, "__file__"))                          \
            die("pygame." #m " was loaded from a shared object, not built in"); \
        Py_DECREF(bm);                                                       \
    }
#include PGFUZZ_INITTAB
#undef PGFUZZ_MOD
#endif

    PyObject *mod = PyImport_ImportModule("pgfuzz");
    if (!mod)
        die("cannot import pgfuzz");
    g_fuzz = PyObject_GetAttrString(mod, "fuzz_" PGFUZZ_TARGET);
    Py_DECREF(mod);
    if (!g_fuzz || !PyCallable_Check(g_fuzz))
        die("pgfuzz has no fuzz_" PGFUZZ_TARGET);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    PyObject *b = PyBytes_FromStringAndSize((const char *)data, (Py_ssize_t)size);
    if (!b)
        die("PyBytes_FromStringAndSize failed");
    PyObject *r = PyObject_CallOneArg(g_fuzz, b);
    Py_DECREF(b);
    if (r) {
        Py_DECREF(r);
    } else {
        /* An exception escaping the driver is a Python-level outcome, not a memory error. */
        PyErr_Clear();
    }
    return 0;
}
