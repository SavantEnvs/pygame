// Leak detection is not the bug class this integration fuzzes for (SPEC §6.2 item 15); CPython
// also keeps interned objects alive until exit by design. ASan and UBSan stay fully active.
extern "C" int __lsan_is_turned_off() { return 1; }
