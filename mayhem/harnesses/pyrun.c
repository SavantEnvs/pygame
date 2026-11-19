/* Python launcher built by mayhem/build.sh (normal flags) so mayhem/test.sh runs pygame's own
 * unittest suite through a project-built executable. Behaves exactly like `python3`. */
#include <Python.h>
int main(int argc, char **argv) { return Py_BytesMain(argc, argv); }
