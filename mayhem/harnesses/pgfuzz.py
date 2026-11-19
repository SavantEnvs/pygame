"""Python-side fuzz drivers for pygame, one ``fuzz_<target>(data: bytes)`` per Mayhem target.

Loaded by mayhem/harnesses/pyfuzz.c, which embeds CPython and imports the sanitized pygame
extension modules.  Each driver decodes the input bytes into a short sequence of PUBLIC pygame API
calls (the only interface pygame has) on objects it creates for that input.  Python exceptions are
the library rejecting bad arguments and are swallowed per call; memory errors and undefined behaviour
in src_c/ are caught by ASan/UBSan.

State kept across inputs, on purpose, and why it is safe:
  * the imported modules and the bytes of the bundled font (read-only);
  * DEAD_DISPLAY, a Surface whose display was quit at start-up, and an uninitialised
    Surface.__new__(Surface).  pygame refuses every operation on them ("display Surface quit",
    "Surface is not initialized"), so no input can change them; they are kept because the upstream
    segfault fixes (draw.c, surface.c, transform.c, mask.c, pixelarray*.c, pixelcopy.c, gfxdraw.c)
    are about exactly these operands.
Everything else (surfaces, masks, fonts, buffers) is created per input and dropped after it.
"""

import io
import struct

import pygame
import pygame.draw
import pygame.gfxdraw
import pygame.image
import pygame.mask
import pygame.math
import pygame.pixelcopy
import pygame.transform
from pygame import Color, Rect, Surface
from pygame.bufferproxy import BufferProxy
from pygame.pixelarray import PixelArray

try:
    import ctypes
except ImportError:  # pragma: no cover
    ctypes = None

pygame.display.init()
try:
    DEAD_DISPLAY = pygame.display.set_mode((16, 16))
except pygame.error:
    DEAD_DISPLAY = Surface((1, 1))
pygame.display.quit()
UNINIT = Surface.__new__(Surface)

import pygame.freetype  # noqa: E402

pygame.freetype.init()
_FONT_PATH = pygame.freetype.get_default_font()
try:
    import os

    with open(os.path.join(os.path.dirname(pygame.__file__), _FONT_PATH), "rb") as _f:
        FONT_BYTES = _f.read()
except OSError:
    FONT_BYTES = None

BLEND_FLAGS = [
    0,
    pygame.BLEND_ADD,
    pygame.BLEND_SUB,
    pygame.BLEND_MULT,
    pygame.BLEND_MIN,
    pygame.BLEND_MAX,
    pygame.BLEND_RGBA_ADD,
    pygame.BLEND_RGBA_SUB,
    pygame.BLEND_RGBA_MULT,
    pygame.BLEND_RGBA_MIN,
    pygame.BLEND_RGBA_MAX,
    pygame.BLEND_PREMULTIPLIED,
    pygame.BLEND_ALPHA_SDL2,
]
DEPTHS = [8, 16, 24, 32, 32, 12, 15, 1]
IMG_FORMATS = ["P", "RGB", "RGBX", "RGBA", "ARGB", "BGRA", "RGBA_PREMULT", "ARGB_PREMULT", "BGR", "XYZ"]
EXPECTED = Exception


class R:
    """Byte reader: every read past the end yields zeros, so any input is a valid program."""

    __slots__ = ("b", "i")

    def __init__(self, b):
        self.b = b
        self.i = 0

    def more(self):
        return self.i < len(self.b)

    def u8(self):
        i = self.i
        self.i = i + 1
        return self.b[i] if i < len(self.b) else 0

    def take(self, n):
        i = self.i
        self.i = i + n
        s = self.b[i : i + n]
        return s + bytes(n - len(s)) if len(s) < n else s

    def u16(self):
        return struct.unpack("<H", self.take(2))[0]

    def i16(self):
        return struct.unpack("<h", self.take(2))[0]

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]

    def i32(self):
        return struct.unpack("<i", self.take(4))[0]

    def f32(self):
        return struct.unpack("<f", self.take(4))[0]

    def f64(self):
        return struct.unpack("<d", self.take(8))[0]

    def num(self):
        """Mostly small values near a small surface, sometimes full int16/int32 range."""
        k = self.u8() & 7
        if k < 5:
            return self.u8() - 32
        if k == 5:
            return self.i16()
        if k == 6:
            return self.i32()
        return (-(2**31), 2**31 - 1, -1, 0, 2**15, -(2**15) - 1, 2**31, 2**63)[self.u8() & 7]

    def small(self, n):
        return self.u8() % n

    def real(self):
        k = self.u8() & 3
        if k == 0:
            return self.f64()
        return (self.u8() - 128) / 8.0

    def pick(self, seq):
        return seq[self.u8() % len(seq)]

    def flag(self):
        return bool(self.u8() & 1)

    def color(self):
        k = self.u8() & 3
        if k == 0:
            return self.u32()
        if k == 1:
            return (self.u8(), self.u8(), self.u8())
        if k == 2:
            return (self.u8(), self.u8(), self.u8(), self.u8())
        return Color(self.u8(), self.u8(), self.u8(), self.u8())

    def point(self):
        return (self.num(), self.num())

    def points(self, maxn=12):
        return [self.point() for _ in range(self.small(maxn))]

    def rect(self):
        return (self.num(), self.num(), self.num(), self.num())

    def text(self, maxn=48):
        raw = self.take(2 * self.small(maxn))
        return raw.decode("utf-16-le", "surrogatepass")


def make_surface(r, maxdim=48):
    """A fresh surface of fuzzed size/depth/flags, pixel bytes from the input."""
    w, h = r.small(maxdim + 1), r.small(maxdim + 1)
    depth = r.pick(DEPTHS)
    flags = pygame.SRCALPHA if r.u8() & 1 else 0
    try:
        if r.u8() & 3 == 0 and depth in (16, 24, 32):
            masks = (r.u32(), r.u32(), r.u32(), r.u32())
            s = Surface((w, h), flags, depth, masks)
        else:
            s = Surface((w, h), flags, depth)
    except EXPECTED:
        s = Surface((w, h))
    n = r.small(255) * 4
    # Fill pixels through the buffer interface; get_buffer() on a zero-area surface trips an
    # assert in bufferproxy.c, which the surface/bufferproxy targets still reach directly.
    if n and w and h:
        data = r.take(n)
        try:
            buf = s.get_buffer()
            ln = min(len(data), buf.length)
            if ln:
                buf.write(data[:ln], 0)
            del buf
        except EXPECTED:
            pass
    return s


def operand(r, pool):
    """Pick a surface operand: mostly from the per-input pool, sometimes a dead one."""
    k = r.u8()
    if k < 12:
        return DEAD_DISPLAY
    if k < 20:
        return UNINIT
    return pool[k % len(pool)]


def run_ops(r, ops, maxops=24):
    for _ in range(maxops):
        if not r.more():
            break
        op = ops[r.u8() % len(ops)]
        try:
            op(r)
        except EXPECTED:
            pass


# --------------------------------------------------------------------------- draw


def fuzz_draw(data):
    r = R(data)
    pool = [make_surface(r), make_surface(r, 16)]
    D = pygame.draw

    def S():
        return operand(r, pool)

    ops = [
        lambda r: D.polygon(S(), r.color(), r.points(), r.num()),
        lambda r: D.circle(S(), r.color(), r.point(), r.num(), r.num(),
                           *(r.flag() for _ in range(4)) if r.flag() else ()),
        lambda r: D.ellipse(S(), r.color(), r.rect(), r.num()),
        lambda r: D.arc(S(), r.color(), r.rect(), r.real(), r.real(), r.num()),
        lambda r: D.line(S(), r.color(), r.point(), r.point(), r.num()),
        lambda r: D.lines(S(), r.color(), r.flag(), r.points(), r.num()),
        lambda r: D.aaline(S(), r.color(), (r.real(), r.real()), (r.real(), r.real()), r.flag()),
        lambda r: D.aalines(S(), r.color(), r.flag(), [(r.real(), r.real()) for _ in range(r.small(8))]),
        lambda r: D.rect(S(), r.color(), r.rect(), r.num(), r.num(), r.num(), r.num(), r.num(), r.num()),
        lambda r: D.rect(S(), r.color(), r.rect(), r.num()),
    ]
    run_ops(r, ops)


# --------------------------------------------------------------------------- surface


def fuzz_surface(data):
    r = R(data)
    pool = [make_surface(r), make_surface(r), make_surface(r, 16)]

    def S():
        return operand(r, pool)

    def blit(r):
        src = S()
        dst = S()
        area = r.rect() if r.flag() else None
        dst.blit(src, r.point(), area, r.pick(BLEND_FLAGS) if r.u8() & 7 else r.i32())

    def blits(r):
        dst = S()
        seq = [(S(), r.point(), r.rect()) if r.flag() else (S(), r.point()) for _ in range(r.small(5))]
        dst.blits(seq, r.flag())

    def sub(r):
        s = S().subsurface(r.rect())
        pool.append(s)
        if r.flag():
            pool.append(s.subsurface(r.rect()))

    def palette(r):
        s = S()
        if r.flag():
            s.set_palette([r.color() for _ in range(r.small(260))])
        else:
            s.set_palette_at(r.num(), r.color())
        s.get_palette()
        s.get_palette_at(r.num())

    def view(r):
        s = S()
        v = s.get_view(r.pick(["0", "1", "2", "3", "r", "g", "b", "a", "R", "G", "B", "A", "x"]))
        m = memoryview(v)
        m.tobytes()
        if not m.readonly and m.nbytes:
            v.write(r.take(r.small(64)), r.small(32))

    def convert(r):
        s = S()
        k = r.u8() % 3
        if k == 0:
            pool.append(s.convert(S()))
        elif k == 1:
            pool.append(s.convert(r.pick(DEPTHS), pygame.SRCALPHA if r.flag() else 0))
        else:
            pool.append(s.convert_alpha(S()))

    ops = [
        blit,
        blit,
        blits,
        lambda r: S().fill(r.color(), r.rect() if r.flag() else None, r.pick(BLEND_FLAGS)),
        sub,
        lambda r: S().scroll(r.num(), r.num()),
        convert,
        lambda r: S().set_at(r.point(), r.color()),
        lambda r: S().get_at(r.point()),
        lambda r: S().get_at_mapped(r.point()),
        palette,
        lambda r: S().set_colorkey(r.color(), r.pick([0, pygame.RLEACCEL])),
        lambda r: S().set_alpha(r.num(), r.pick([0, pygame.RLEACCEL])),
        lambda r: pool.append(S().premul_alpha()),
        view,
        lambda r: pool.append(S().copy()),
        lambda r: S().get_bounding_rect(r.num()),
        lambda r: S().unmap_rgb(S().map_rgb(r.color())),
        lambda r: S().set_clip(r.rect()),
        lambda r: (S().get_buffer().raw),
        lambda r: S().get_locks(),
    ]
    run_ops(r, ops, 32)


# --------------------------------------------------------------------------- transform


def fuzz_transform(data):
    r = R(data)
    pool = [make_surface(r), make_surface(r, 16)]
    T = pygame.transform

    def S():
        return operand(r, pool)

    def size():
        return (r.small(130) - 2, r.small(130) - 2)

    def keep(s):
        if isinstance(s, Surface):
            pool.append(s)

    def threshold(r):
        T.threshold(S() if r.flag() else None, S(), r.color(), r.color(), r.color(),
                    r.small(3), S() if r.flag() else None, r.flag())

    ops = [
        lambda r: keep(T.scale(S(), size(), S() if r.u8() < 40 else None)),
        lambda r: keep(T.scale_by(S(), (r.u8() - 64) / 16.0)),
        lambda r: keep(T.smoothscale(S(), size(), S() if r.u8() < 40 else None)),
        lambda r: keep(T.smoothscale_by(S(), (r.u8() - 64) / 16.0)),
        lambda r: keep(T.rotate(S(), r.real())),
        lambda r: keep(T.rotozoom(S(), r.real(), (r.u8() - 64) / 32.0)),
        lambda r: keep(T.flip(S(), r.flag(), r.flag())),
        lambda r: keep(T.chop(S(), r.rect())),
        lambda r: keep(T.scale2x(S(), S() if r.u8() < 40 else None)),
        lambda r: keep(T.laplacian(S(), S() if r.u8() < 40 else None)),
        lambda r: T.average_surfaces([S() for _ in range(r.small(4))], S() if r.flag() else None, r.small(2)),
        lambda r: T.average_color(S(), r.rect() if r.flag() else None, r.flag()),
        lambda r: keep(T.grayscale(S(), S() if r.u8() < 40 else None)),
        threshold,
        lambda r: T.set_smoothscale_backend(r.pick(["GENERIC", "SSE2", "MMX", "SSE"])),
    ]
    try:
        run_ops(r, ops)
    finally:
        T.set_smoothscale_backend("GENERIC")


# --------------------------------------------------------------------------- mask


def fuzz_mask(data):
    r = R(data)
    M = pygame.mask
    surfs = [make_surface(r, 32)]

    def new_mask():
        k = r.u8() % 3
        if k == 0:
            w, h = r.small(80), r.small(80)
            m = M.Mask((w, h), r.flag())
            bits = r.take(r.small(64))
            for i, byte in enumerate(bits):
                if w and h:
                    m.set_at(((i * 7 + byte) % w, (byte * 3 + i) % h), byte & 1)
            return m
        if k == 1:
            return M.from_surface(surfs[0] if r.u8() > 30 else DEAD_DISPLAY, r.u8())
        return M.from_threshold(surfs[0] if r.u8() > 30 else UNINIT, r.color(), r.color(),
                                surfs[0] if r.flag() else None, r.small(2))

    try:
        masks = [new_mask(), new_mask()]
    except EXPECTED:
        masks = [M.Mask((8, 8), True), M.Mask((3, 5))]

    def K():
        return masks[r.u8() % len(masks)]

    def to_surface(r):
        K().to_surface(
            r.pick([None, surfs[0], DEAD_DISPLAY, UNINIT]),
            r.pick([None, surfs[0], DEAD_DISPLAY]),
            r.pick([None, surfs[0], UNINIT]),
            r.color() if r.flag() else None,
            r.color() if r.flag() else None,
            r.point(),
        )

    ops = [
        lambda r: K().overlap(K(), r.point()),
        lambda r: K().overlap_area(K(), r.point()),
        lambda r: masks.append(K().overlap_mask(K(), r.point())),
        lambda r: K().draw(K(), r.point()),
        lambda r: K().erase(K(), r.point()),
        lambda r: masks.append(K().convolve(K(), K() if r.flag() else None, r.point())),
        lambda r: K().outline(r.num()),
        lambda r: masks.append(K().connected_component(r.point() if r.flag() else None)),
        lambda r: masks.extend(K().connected_components(r.num())[:4]),
        lambda r: K().get_bounding_rects(),
        lambda r: masks.append(K().scale((r.small(100), r.small(100)))),
        to_surface,
        lambda r: K().set_at(r.point(), r.u8() & 1),
        lambda r: K().get_at(r.point()),
        lambda r: (K().fill(), K().clear(), K().invert()),
        lambda r: (K().count(), K().centroid(), K().angle(), K().get_rect()),
        lambda r: masks.append(K().copy()),
        lambda r: masks.append(new_mask()),
    ]
    run_ops(r, ops)


# --------------------------------------------------------------------------- pixelarray


def fuzz_pixelarray(data):
    r = R(data)
    surfs = [make_surface(r, 32), make_surface(r, 16)]
    arrays = []
    for s in surfs + ([DEAD_DISPLAY] if r.u8() < 30 else []):
        try:
            arrays.append(PixelArray(s))
        except EXPECTED:
            pass
    if not arrays:
        return

    def A():
        return arrays[r.u8() % len(arrays)]

    def idx():
        k = r.u8() % 6
        if k == 0:
            return r.num()
        if k == 1:
            return slice(r.num() if r.flag() else None, r.num() if r.flag() else None,
                         r.num() if r.flag() else None)
        if k == 2:
            return (r.num(), r.num())
        if k == 3:
            return (slice(r.num(), r.num(), r.num() or None), r.num())
        if k == 4:
            return (slice(r.num(), r.num(), r.num() or None), slice(r.num(), r.num(), r.num() or None))
        return Ellipsis

    def value():
        k = r.u8() % 5
        if k == 0:
            return r.u32()
        if k == 1:
            return r.color()
        if k == 2:
            return [r.color() for _ in range(r.small(6))]
        if k == 3:
            return A()
        return [r.u32() for _ in range(r.small(40))]

    def get(r):
        v = A()[idx()]
        if isinstance(v, PixelArray):
            arrays.append(v)

    def weights():
        return (r.real(), r.real(), r.real())

    ops = [
        get,
        get,
        lambda r: A().__setitem__(idx(), value()),
        lambda r: A().__setitem__(idx(), value()),
        lambda r: A().replace(r.color(), r.color(), r.real(), weights()),
        lambda r: arrays.append(A().extract(r.color(), r.real(), weights())),
        lambda r: arrays.append(A().compare(A(), r.real(), weights())),
        lambda r: arrays.append(A().transpose()),
        lambda r: A().make_surface(),
        lambda r: (A().shape, A().strides, A().ndim, A().itemsize, len(A())),
        lambda r: A().close(),
        lambda r: bytes(memoryview(A())),
        lambda r: A().__delitem__(idx()),
        lambda r: (r.u32() in A()),
        lambda r: list(iter(A()))[:4],
    ]
    try:
        run_ops(r, ops)
    finally:
        for a in arrays:
            try:
                a.close()
            except EXPECTED:
                pass


# --------------------------------------------------------------------------- image


def fuzz_image(data):
    r = R(data)
    I = pygame.image
    fmt = r.pick(IMG_FORMATS)
    w, h = r.small(64), r.small(64)
    flipped = r.flag()
    k = r.u8() % 3
    payload = r.b[r.i : r.i + 16384]
    r.i += r.small(4) * 256
    surfs = []
    try:
        if k == 0:
            surfs.append(I.frombuffer(bytearray(payload), (w, h), fmt))
        elif k == 1:
            surfs.append(I.frombytes(bytes(payload), (w, h), fmt, flipped))
        else:
            surfs.append(I.fromstring(bytes(payload), (w, h), fmt, flipped))
    except EXPECTED:
        pass
    pool = surfs + [make_surface(r, 32)]

    def S():
        return operand(r, pool)

    def save(r):
        bio = io.BytesIO()
        I.save(S(), bio, r.pick(["x.tga", "x.bmp", "x.TGA", "x", "x.png"]))
        out = bio.getvalue()
        if out:
            pool.append(I.load(io.BytesIO(out), "x.bmp"))

    ops = [
        lambda r: I.tobytes(S(), r.pick(IMG_FORMATS), r.flag()),
        lambda r: I.tostring(S(), r.pick(IMG_FORMATS), r.flag()),
        save,
        lambda r: pool.append(I.load(io.BytesIO(r.b[r.i :]), r.pick(["x.bmp", "x.tga", "x"]))),
        lambda r: pool.append(I.frombytes(r.take(r.small(255) * 4), (r.small(40), r.small(40)),
                                          r.pick(IMG_FORMATS), r.flag())),
        lambda r: pool.append(I.frombuffer(bytearray(r.take(r.small(255) * 4)),
                                           (r.small(40), r.small(40)), r.pick(IMG_FORMATS))),
    ]
    run_ops(r, ops, 12)


# --------------------------------------------------------------------------- gfxdraw


def fuzz_gfxdraw(data):
    r = R(data)
    pool = [make_surface(r), make_surface(r, 16)]
    G = pygame.gfxdraw

    def S():
        return operand(r, pool)

    def n():
        return r.num()

    def c():
        return r.color()

    def pts():
        return r.points(10)

    ops = [
        lambda r: G.pixel(S(), n(), n(), c()),
        lambda r: G.hline(S(), n(), n(), n(), c()),
        lambda r: G.vline(S(), n(), n(), n(), c()),
        lambda r: G.line(S(), n(), n(), n(), n(), c()),
        lambda r: G.rectangle(S(), r.rect(), c()),
        lambda r: G.box(S(), r.rect(), c()),
        lambda r: G.circle(S(), n(), n(), n(), c()),
        lambda r: G.aacircle(S(), n(), n(), n(), c()),
        lambda r: G.filled_circle(S(), n(), n(), n(), c()),
        lambda r: G.ellipse(S(), n(), n(), n(), n(), c()),
        lambda r: G.aaellipse(S(), n(), n(), n(), n(), c()),
        lambda r: G.filled_ellipse(S(), n(), n(), n(), n(), c()),
        lambda r: G.arc(S(), n(), n(), n(), n(), n(), c()),
        lambda r: G.pie(S(), n(), n(), n(), n(), n(), c()),
        lambda r: G.trigon(S(), n(), n(), n(), n(), n(), n(), c()),
        lambda r: G.aatrigon(S(), n(), n(), n(), n(), n(), n(), c()),
        lambda r: G.filled_trigon(S(), n(), n(), n(), n(), n(), n(), c()),
        lambda r: G.polygon(S(), pts(), c()),
        lambda r: G.aapolygon(S(), pts(), c()),
        lambda r: G.filled_polygon(S(), pts(), c()),
        lambda r: G.textured_polygon(S(), pts(), S(), n(), n()),
        lambda r: G.bezier(S(), pts(), n(), c()),
    ]
    run_ops(r, ops)


# --------------------------------------------------------------------------- math


SWZ = "xyzw01"


def fuzz_math(data):
    r = R(data)
    V2, V3 = pygame.math.Vector2, pygame.math.Vector3

    def new_vec():
        k = r.u8() % 5
        cls = V2 if r.flag() else V3
        if k == 0:
            return cls(r.take(r.small(48)).decode("latin-1"))
        if k == 1:
            return cls(*[r.real() for _ in range(r.small(4))])
        if k == 2:
            return cls([r.real() for _ in range(r.small(5))])
        if k == 3:
            return cls(r.real())
        return cls(repr(cls(r.real(), r.real(), *([r.real()] if cls is V3 else []))))

    vecs = []
    for _ in range(3):
        try:
            vecs.append(new_vec())
        except EXPECTED:
            vecs.append(V2(1, 2))

    def V():
        return vecs[r.u8() % len(vecs)]

    def swz():
        return "".join(SWZ[r.u8() % 6] for _ in range(1 + r.small(6)))

    def keep(v):
        if isinstance(v, (V2, V3)):
            vecs.append(v)

    def sl():
        return slice(r.num() if r.flag() else None, r.num() if r.flag() else None,
                     r.num() if r.flag() else None)

    ops = [
        lambda r: keep(getattr(V(), swz())),
        lambda r: setattr(V(), swz(), [r.real() for _ in range(r.small(6))] if r.flag() else r.real()),
        lambda r: V()[sl()],
        lambda r: V().__setitem__(sl(), [r.real() for _ in range(r.small(5))]),
        lambda r: V()[r.num()],
        lambda r: V().distance_to(V() if r.flag() else [r.real() for _ in range(r.small(4))]),
        lambda r: V().distance_squared_to(V()),
        lambda r: keep(V().rotate(r.real())),
        lambda r: keep(V().rotate_rad(r.real())),
        lambda r: V().rotate_ip(r.real()),
        lambda r: keep(V3(r.real(), r.real(), r.real()).rotate(r.real(), V())),
        lambda r: keep(V().slerp(V(), r.real())),
        lambda r: keep(V().lerp(V(), r.real())),
        lambda r: keep(V().clamp_magnitude(r.real()) if r.flag() else V().clamp_magnitude(r.real(), r.real())),
        lambda r: V().clamp_magnitude_ip(r.real()),
        lambda r: keep(V2.from_polar((r.real(), r.real()))),
        lambda r: keep(V3.from_spherical((r.real(), r.real(), r.real()))),
        lambda r: V2().from_polar((r.real(), r.real())),
        lambda r: (V().as_polar() if isinstance(V(), V2) else V().as_spherical()),
        lambda r: keep(V().elementwise() * V() + r.real()),
        lambda r: keep(V().elementwise() ** r.real()),
        lambda r: keep(V().elementwise() // V()),
        lambda r: keep(V().elementwise() % r.real()),
        lambda r: keep(V().reflect(V())),
        lambda r: keep(V().project(V())),
        lambda r: V().angle_to(V()),
        lambda r: V().cross(V()),
        lambda r: V().dot(V()),
        lambda r: keep(V().normalize()),
        lambda r: V().scale_to_length(r.real()),
        lambda r: keep(V().move_towards(V(), r.real())),
        lambda r: V().update(*[r.real() for _ in range(r.small(4))]),
        lambda r: (V() == V(), V() < V(), hash(tuple(V()))),
        lambda r: keep(V() * V() if r.flag() else V() * r.real()),
        lambda r: keep(V() / r.real()),
        lambda r: pygame.math.clamp(r.real(), r.real(), r.real()),
        lambda r: pygame.math.lerp(r.real(), r.real(), r.real()),
        lambda r: (str(V()), repr(V()), V().epsilon, setattr(V(), "epsilon", r.real())),
        lambda r: keep(new_vec()),
    ]
    run_ops(r, ops, 32)


# --------------------------------------------------------------------------- color + rect


COLOR_ATTRS = ["hsva", "hsla", "cmy", "i1i2i3", "r", "g", "b", "a"]
RECT_ATTRS = ["x", "y", "w", "h", "top", "left", "bottom", "right", "center", "centerx",
              "centery", "size", "width", "height", "topleft", "bottomright", "midtop", "midleft"]


def fuzz_colorrect(data):
    r = R(data)

    def new_color():
        k = r.u8() % 5
        if k == 0:
            return Color(r.take(r.small(24)).decode("latin-1"))
        if k == 1:
            return Color(r.pick(["#", "0x", "", "#ff", "0xff"]) + r.take(r.small(10)).hex())
        if k == 2:
            return Color(r.u32() if r.flag() else r.num())
        if k == 3:
            return Color(*[r.num() for _ in range(r.small(5))])
        return Color([r.u8() for _ in range(r.small(6))])

    colors = []
    for _ in range(2):
        try:
            colors.append(new_color())
        except EXPECTED:
            colors.append(Color(1, 2, 3, 4))

    def C():
        return colors[r.u8() % len(colors)]

    def tup(n):
        return tuple(r.real() if r.flag() else r.num() for _ in range(n))

    rects = [Rect(r.num(), r.num(), r.num(), r.num()) for _ in range(2)]

    def RR():
        return rects[r.u8() % len(rects)]

    def rlist():
        return [RR() if r.flag() else r.rect() for _ in range(r.small(5))]

    ops = [
        lambda r: setattr(C(), r.pick(COLOR_ATTRS), tup(r.small(5)) if r.flag() else r.num()),
        lambda r: (getattr(C(), r.pick(COLOR_ATTRS))),
        lambda r: colors.append(C().lerp(C() if r.flag() else r.color(), r.real())),
        lambda r: colors.append(C().correct_gamma(r.real())),
        lambda r: colors.append(C().premul_alpha()),
        lambda r: C().set_length(r.num()),
        lambda r: C()[slice(r.num(), r.num(), r.num() or None)],
        lambda r: C().__setitem__(r.num(), r.num()),
        lambda r: (C().normalize(), bytes(C()), int(C()), str(C()), C() == C()),
        lambda r: C().update(*[r.num() for _ in range(r.small(5))]),
        lambda r: colors.append(C() + C() if r.flag() else C() * C()),
        lambda r: colors.append(C() // C() if r.flag() else C() % C()),
        lambda r: colors.append(~C()),
        lambda r: colors.append(new_color()),
        lambda r: rects.append(RR().clip(RR() if r.flag() else r.rect())),
        lambda r: RR().clipline(*(r.rect() if r.flag() else (r.point(), r.point()))),
        lambda r: rects.append(RR().union(RR())),
        lambda r: rects.append(RR().unionall(rlist())),
        lambda r: RR().unionall_ip(rlist()),
        lambda r: RR().collidepoint(r.point()),
        lambda r: RR().colliderect(RR()),
        lambda r: RR().collidelist(rlist()),
        lambda r: RR().collidelistall(rlist()),
        lambda r: RR().collidedict({i: x for i, x in enumerate(rlist())}, r.flag()),
        lambda r: RR().collidedictall({i: x for i, x in enumerate(rlist())}, r.flag()),
        lambda r: RR().collideobjects(rlist(), key=(lambda o: o) if r.flag() else None),
        lambda r: RR().collideobjectsall(rlist(), key=(lambda o: o) if r.flag() else None),
        lambda r: rects.append(RR().fit(RR())),
        lambda r: RR().contains(RR()),
        lambda r: rects.append(RR().inflate(r.num(), r.num())),
        lambda r: rects.append(RR().scale_by(r.real(), r.real())),
        lambda r: rects.append(RR().move(r.num(), r.num())),
        lambda r: rects.append(RR().clamp(RR())),
        lambda r: RR().normalize(),
        lambda r: RR().update(*rlist()[:1] or r.rect()),
        lambda r: setattr(RR(), r.pick(RECT_ATTRS), r.num() if r.flag() else r.point()),
        lambda r: RR()[slice(r.num(), r.num(), r.num() or None)],
        lambda r: RR().__setitem__(r.num(), r.num()),
        lambda r: RR().__setitem__(slice(r.num(), r.num()), [r.num() for _ in range(r.small(5))]),
        lambda r: rects.append(Rect(r.rect())),
    ]
    run_ops(r, ops, 32)


# --------------------------------------------------------------------------- pixelcopy

ARRAY_FMTS = ["B", "b", "H", "h", "I", "i", "Q", "q", "f", "d", "c"]


def make_array(r):
    """A writable 2-D/3-D buffer exporter of fuzzed format and shape (owned memory)."""
    fmt = r.pick(ARRAY_FMTS)
    nd = 2 + (r.u8() & 1)
    shape = [r.small(40) for _ in range(nd)]
    if nd == 3:
        shape[2] = r.small(5)
    size = struct.calcsize(fmt)
    count = 1
    for d in shape:
        count *= d
    mv = memoryview(bytearray(r.take(r.small(64)) + bytes(count * size))[: count * size or size])
    if count == 0:
        return mv.cast(fmt)
    return mv.cast("B").cast(fmt, shape)


def fuzz_pixelcopy(data):
    r = R(data)
    P = pygame.pixelcopy
    pool = [make_surface(r, 32), make_surface(r, 16)]
    arrays = []
    for _ in range(2):
        try:
            arrays.append(make_array(r))
        except EXPECTED:
            pass
    if not arrays:
        arrays.append(memoryview(bytearray(16)).cast("B", [4, 4]))

    def S():
        return operand(r, pool)

    def A():
        return arrays[r.u8() % len(arrays)]

    ops = [
        lambda r: P.array_to_surface(S(), A()),
        lambda r: P.surface_to_array(A(), S(), r.pick(["P", "R", "G", "B", "A", "C", "X"]), r.num(), r.num()),
        lambda r: P.map_array(A(), A(), S()),
        lambda r: pool.append(P.make_surface(A())),
        lambda r: arrays.append(make_array(r)),
        lambda r: P.array_to_surface(S(), S().get_view(r.pick(["2", "3", "r", "a"]))),
        lambda r: P.surface_to_array(S().get_view(r.pick(["2", "3"])), S(), r.pick(["P", "R", "A", "C"])),
    ]
    run_ops(r, ops)


# --------------------------------------------------------------------------- freetype


def fuzz_freetype(data):
    if FONT_BYTES is None:
        return
    r = R(data)
    F = pygame.freetype
    try:
        font = F.Font(io.BytesIO(FONT_BYTES), r.small(64), resolution=r.small(200))
    except EXPECTED:
        return
    pool = [make_surface(r, 32)]

    def S():
        return operand(r, pool)

    def style():
        return r.u8() & 0x0F if r.u8() & 7 else r.u16()

    def size():
        k = r.u8() % 4
        if k == 0:
            return 0
        if k == 1:
            return r.small(80)
        if k == 2:
            return (r.small(80), r.small(80))
        return r.u8() / 3.0

    def rot():
        return r.num()

    def setattrs(r):
        name = r.pick(["size", "style", "strength", "underline_adjustment", "rotation", "fgcolor",
                       "bgcolor", "antialiased", "kerning", "vertical", "pad", "origin", "wide",
                       "oblique", "strong", "underline", "ucs4", "use_bitmap_strikes"])
        val = {"fgcolor": r.color, "bgcolor": r.color, "size": size}.get(name, lambda: r.real() if r.flag() else r.num())()
        if name == "size" and isinstance(val, (int, float)) and val > 80:
            val = 80
        setattr(font, name, val)

    def render_raw_to(r):
        w, h = r.small(64), r.small(64)
        fmt = r.pick(["B", "H", "I", "b"])
        mv = memoryview(bytearray(w * h * struct.calcsize(fmt) or 1))
        arr = mv.cast(fmt, [w, h]) if w * h else mv
        font.render_raw_to(arr, r.text(), r.point() if r.flag() else None, style(), rot(), size(), r.flag())

    ops = [
        setattrs,
        setattrs,
        lambda r: font.render(r.text(), r.color(), r.color() if r.flag() else None, style(), rot(), size()),
        lambda r: font.render_to(S(), r.point() if r.flag() else r.rect(), r.text(), r.color(),
                                 r.color() if r.flag() else None, style(), rot(), size()),
        lambda r: font.render_raw(r.text(), style(), rot(), size(), r.flag()),
        render_raw_to,
        lambda r: font.get_rect(r.text(), style(), rot(), size()),
        lambda r: font.get_metrics(r.text(), size()),
        lambda r: (font.get_sized_ascender(size()), font.get_sized_descender(size()),
                   font.get_sized_height(size()), font.get_sized_glyph_height(size())),
        lambda r: font.get_sizes(),
    ]
    run_ops(r, ops, 16)


# --------------------------------------------------------------------------- bufferproxy

KINDS = "biufcV"


def fuzz_bufferproxy(data):
    r = R(data)
    pool = [make_surface(r, 32)]
    proxies = []

    def new_proxy():
        nd = r.small(4)
        itemsize = 1 + r.small(16)
        kind = r.pick(KINDS)
        endian = r.pick("<>|=")
        typestr = "%s%s%d" % (endian, kind, itemsize)
        shape = tuple(r.small(9) for _ in range(nd))
        if r.flag():
            strides = tuple(r.small(64) for _ in range(nd))
        else:
            strides = None
        # Owned backing store large enough for every element the dict describes.
        extent = itemsize
        if strides is None:
            for d in shape:
                extent *= d
        else:
            if all(shape):
                extent = itemsize + sum((d - 1) * s for d, s in zip(shape, strides))
        backing = bytearray(r.take(r.small(32)) + bytes(extent + 1))
        if ctypes is None:
            return None
        addr = ctypes.addressof((ctypes.c_char * len(backing)).from_buffer(backing))
        d = {"typestr": typestr, "shape": shape, "data": (addr, r.flag()), "parent": backing}
        if strides is not None:
            d["strides"] = strides
        if r.flag():
            d["before"] = lambda p: None
            d["after"] = lambda p: None
        bp = BufferProxy(d)
        proxies.append((bp, backing))
        return bp

    def P():
        if not proxies:
            new_proxy()
        return proxies[r.u8() % len(proxies)][0]

    def write(r):
        p = P()
        p.write(r.take(r.small(40)), r.num())

    ops = [
        lambda r: new_proxy(),
        lambda r: P().raw,
        lambda r: P().length,
        lambda r: (P().__array_interface__, P().__array_struct__),
        lambda r: memoryview(P()).tobytes(),
        lambda r: memoryview(P()).cast("B"),
        write,
        lambda r: P().parent,
        lambda r: proxies.append((operand(r, pool).get_view(r.pick("0123rgbaRGBAx")), None)),
        lambda r: proxies.append((operand(r, pool).get_buffer(), None)),
        lambda r: repr(P()),
    ]
    try:
        run_ops(r, ops)
    finally:
        proxies.clear()
