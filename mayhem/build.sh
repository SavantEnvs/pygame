#!/usr/bin/env bash
# mayhem/build.sh — build pygame twice (sanitized for fuzzing, normal flags for the test suite) and
# the embedded-CPython fuzz harnesses. Runs in /mayhem as `mayhem`; offline, re-runnable.
#
#   build/fuzz/lib   pygame package, every C extension built with ASan+UBSan + SanCov, DWARF 3
#   build/test/lib   pygame package with upstream's normal flags (the mayhem/test.sh oracle)
#   /mayhem/fuzz_<t>, /mayhem/fuzz_<t>-standalone   one libFuzzer target per pygame API group
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export CC CXX

cd "$SRC"

TARGETS="draw surface transform mask pixelarray image gfxdraw math colorrect pixelcopy freetype bufferproxy"

# Coverage for the extension modules: SanCov without the libFuzzer runtime (the harness links it).
# Only when sanitizers are on, so an empty SANITIZER_FLAGS gives a plain build.
# Three UBSan checks are relaxed for the pygame objects only, because they fire on benign idioms on
# almost every input and would halt before any deeper code is reached:
#   shift-base        surface.c builds its default 32-bit masks as `0xFF << 24` (int), so EVERY
#                     SRCALPHA Surface() trips it;
#   pointer-overflow  `pixels + offset` arithmetic on a zero-sized surface, whose pixels are NULL
#                     (surface.c, transform.c, mask.c, image.c, pixelarray_methods.c: NULL + 0).
#   nonnull-attribute the same zero-sized surfaces reach `memcpy(dst, NULL, 0)` (image.c tobytes,
#                     transform.c flip, ...), a no-op copy that halted image/transform within a second
#                     of every run, so those targets never got past it.
# shift-exponent, signed-integer-overflow and the rest of UBSan, and all of ASan, stay halting.
SANCOV=""
[ -n "$SANITIZER_FLAGS" ] && SANCOV="-fsanitize=fuzzer-no-link -fno-sanitize=shift-base,pointer-overflow,nonnull-attribute"

copy_data() {  # setup.py `build` does not stage package data; the font and test fixtures are needed
  local lib="$1"
  cp -f src_py/freesansbold.ttf src_py/pygame_icon.bmp src_py/pygame.ico "$lib/pygame/"
  rm -rf "$lib/pygame/tests/fixtures" "$lib/pygame/examples/data"
  cp -r test/fixtures "$lib/pygame/tests/fixtures"
  cp -r examples/data "$lib/pygame/examples/data"
}

# setup.py writes ./Setup from buildconfig/ on first run (gitignored; recreated after git clean).
# 1) sanitized pygame for the fuzz targets
env CFLAGS="$SANITIZER_FLAGS $SANCOV $DEBUG_FLAGS" LDSHARED="$CC -shared" \
  python3 setup.py build --build-base build/fuzz --build-lib build/fuzz/lib -j"$MAYHEM_JOBS"
copy_data build/fuzz/lib

# 2) the same tree with upstream's normal flags, for the functional suite
env CFLAGS="-O2 $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" LDSHARED="$CC -shared" \
  python3 setup.py build --build-base build/test --build-lib build/test/lib -j"$MAYHEM_JOBS"
copy_data build/test/lib
# shellcheck disable=SC2046
$CC -O2 $COVERAGE_FLAGS $(python3-config --includes) mayhem/harnesses/pyrun.c \
  $(python3-config --embed --ldflags) -o build/test/pgpython

# 3) harnesses: libFuzzer binary + standalone reproducer per target
PYINC="$(python3-config --includes)"
PYLIB="$(python3-config --embed --ldflags)"
mkdir -p build/harness

# The fuzzed extension modules are linked INTO each harness executable (as built-in modules
# `pygame.<m>`, see PGFUZZ_INITTAB in pyfuzz.c) rather than dlopen'd from build/fuzz/lib: Mayhem
# measures edges in the main executable, and with every module dlopen'd most targets recorded
# 0 edges there although they fuzzed.  The objects are the sanitized ones setup.py just built
# (step 1); the module -> sources map is read from ./Setup, which setup.py generated.  Modules
# left out (font, imageext, mixer, scrap, _camera, _sprite, _sdl2) still load from build/fuzz/lib.
#
# As separate .so files each module had its own private copy of every global it defines; in one
# executable those collide.  So, per module, llvm-objcopy renames (in all of that module's objects,
# definitions and references alike) every global symbol that another linked-in module also defines
# (the `_PGSLOTS_<api>` C-API slot pointers and their ASan ODR indicators), and PyInit_<m> to
# PyInit_pgfuzz_<m>, which also keeps pygame.time/pygame.math off CPython's own PyInit_time/
# PyInit_math.  llvm-objcopy, not GNU objcopy: the latter breaks clang's ASan COMDAT groups.
STATIC_MODS="base constants rect rwobject surflock color bufferproxy math surface display draw event
  key mouse time joystick image transform mask pixelarray pixelcopy newbuffer gfxdraw _freetype"
tmpdir=$(ls -d build/fuzz/temp.*/ | head -n1)
SD=build/harness/static
rm -rf "$SD"
mkdir -p "$SD"
: > build/harness/pgfuzz_inittab.h
for m in $STATIC_MODS; do
  # Setup lines are `<module> <sources/flags...>`, with `$(VAR)` macros from `VAR = ...` lines
  # (gfxdraw's SDL_gfx sources come in through `$(GFX)`).
  srcs=$(awk -v m="$m" '
    $2 == "=" { v = $0; sub(/^[^=]*= */, "", v); var[$1] = v; next }
    $1 == m { for (i = 2; i <= NF; i++) {
                t = $i
                if (t ~ /^\$\(.*\)$/) { k = substr(t, 3, length(t) - 3); n = split(var[k], e, " ")
                                         for (j = 1; j <= n; j++) if (e[j] ~ /^src_c\/.*\.c$/) print e[j] }
                else if (t ~ /^src_c\/.*\.c$/) print t } }' Setup)
  [ -n "$srcs" ] || { echo "build.sh: module $m not in ./Setup" >&2; exit 1; }
  mkdir -p "$SD/$m"
  for src in $srcs; do
    obj="$tmpdir${src%.c}.o"
    [ -f "$obj" ] || { echo "build.sh: missing $obj" >&2; exit 1; }
    cp -f "$obj" "$SD/$m/$(basename "${src%.c}").o"
  done
  # strong definitions only: weak ones (ASan's ___asan_globals_registered, COMDAT ctors) are
  # meant to be merged across the whole executable and must keep their names.
  llvm-nm --defined-only --extern-only --format=posix "$SD/$m"/*.o \
    | awk 'NF >= 2 && $2 ~ /^[BDTRG]$/ { print $1 }' | sort -u > "$SD/$m.syms"
  echo "PGFUZZ_MOD($m)" >> build/harness/pgfuzz_inittab.h
done
cat "$SD"/*.syms | sort | uniq -d > "$SD/shared.syms"
STATIC_OBJS=()
for m in $STATIC_MODS; do
  { echo "PyInit_$m PyInit_pgfuzz_$m"
    comm -12 "$SD/$m.syms" "$SD/shared.syms" | awk -v m="$m" '{ print $1, $1 "__pgfuzz_" m }'
  } > "$SD/$m.rename"
  for o in "$SD/$m"/*.o; do
    llvm-objcopy --redefine-syms="$SD/$m.rename" "$o"
    STATIC_OBJS+=("$o")
  done
done
STATIC_LIBS="$(pkg-config --libs sdl2 freetype2) -lm"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o build/harness/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o build/harness/standalone_main.o
for t in $TARGETS; do
  defs=(-DPGFUZZ_TARGET="\"$t\"" -DPGFUZZ_LIBDIR="\"$SRC/build/fuzz/lib\"" -DPGFUZZ_PYDIR="\"$SRC/mayhem/harnesses\""
        -DPGFUZZ_INITTAB="\"$SRC/build/harness/pgfuzz_inittab.h\"")
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE $PYINC "${defs[@]}" mayhem/harnesses/pyfuzz.c \
    build/harness/lsan_off.o "${STATIC_OBJS[@]}" $STATIC_LIBS $PYLIB -o "$SRC/fuzz_$t"
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $PYINC "${defs[@]}" mayhem/harnesses/pyfuzz.c \
    build/harness/standalone_main.o build/harness/lsan_off.o "${STATIC_OBJS[@]}" $STATIC_LIBS $PYLIB -lstdc++ \
    -o "$SRC/fuzz_$t-standalone"
done
echo "built: $(for t in $TARGETS; do printf 'fuzz_%s ' "$t"; done)"
