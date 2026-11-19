"""Run pygame's own unittest modules for the API the fuzz targets cover; print one summary line.

Run by mayhem/test.sh through build/test/pgpython (a project-built interpreter launcher) against
build/test/lib (pygame built with normal flags).  Two upstream tests are deselected because they
need the host environment, not pygame code:
  freetype_test...test_freetype_SysFont_name   needs installed system fonts (the image has none)
  freetype_test...test_garbage_collection      raises NameError (`sys` not imported) on Python 3.13
"""
import sys
import unittest

MODULES = [
    "base", "blit", "bufferproxy", "color", "draw", "gfxdraw", "image", "mask", "math",
    "pixelarray", "pixelcopy", "rect", "surface", "transform", "freetype", "rwobject",
    "surflock", "sprite",
]
DESELECT = {
    "pygame.tests.freetype_test.FreeTypeFontTest.test_freetype_SysFont_name",
    "pygame.tests.freetype_test.FreeTypeFontTest.test_garbage_collection",
}


def flatten(suite):
    for t in suite:
        if isinstance(t, unittest.TestSuite):
            yield from flatten(t)
        else:
            yield t


def main():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for m in MODULES:
        for t in flatten(loader.loadTestsFromName("pygame.tests.%s_test" % m)):
            if t.id() not in DESELECT:
                suite.addTest(t)
    res = unittest.TextTestRunner(verbosity=1, stream=sys.stdout).run(suite)
    failed = len(res.failures) + len(res.errors) + len(res.unexpectedSuccesses)
    skipped = len(res.skipped)
    passed = res.testsRun - failed - skipped
    print("PGTEST passed=%d failed=%d skipped=%d" % (passed, failed, skipped))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
