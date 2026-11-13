"""Draws the MatrixSys icon (glowing wireframe octahedron on a dark grid tile) and writes matrixsys.ico.
Pure standard library: the 256 px image is stored as PNG, smaller sizes as 32-bit bitmaps."""
import math, os, struct, zlib

HERE = os.path.dirname(os.path.abspath(__file__))


def render(n):
    yaw, pitch = math.radians(32), math.radians(24)
    verts = [(1, 0, 0), (-1, 0, 0), (0, 1.25, 0), (0, -1.25, 0), (0, 0, 1), (0, 0, -1)]
    pts = []
    for x, y, z in verts:
        x, z = x * math.cos(yaw) + z * math.sin(yaw), -x * math.sin(yaw) + z * math.cos(yaw)
        y, z = y * math.cos(pitch) - z * math.sin(pitch), y * math.sin(pitch) + z * math.cos(pitch)
        pts.append((n / 2 + x * n * 0.3, n / 2 - y * n * 0.3, z))
    edges = [(a, b) for a in range(6) for b in range(a + 1, 6) if a // 2 != b // 2]
    segs = [(pts[a][0], pts[a][1], pts[b][0], pts[b][1], 0.55 + 0.45 * ((pts[a][2] + pts[b][2]) / 2 + 1) / 2) for a, b in edges]
    core, glow = max(0.6, n / 110), max(1.2, n / 22)
    rad, grid = n * 0.2, n / 8
    px = bytearray(n * n * 4)
    for j in range(n):
        for i in range(n):
            x, y = i + 0.5, j + 0.5
            # rounded-square tile with soft edge
            dx, dy = max(abs(x - n / 2) - (n / 2 - rad), 0), max(abs(y - n / 2) - (n / 2 - rad), 0)
            a = min(1.0, max(0.0, rad - math.hypot(dx, dy) + 0.5))
            if a <= 0:
                continue
            edge = max(0.0, 1 - abs(rad - math.hypot(dx, dy) - n * 0.03) / max(1.0, n * 0.02)) if n >= 32 else 0
            t = y / n
            r, g, b = 0.004 + 0.02 * t, 0.03 + 0.07 * t, 0.07 + 0.16 * t
            if n >= 48:   # faint perspective-less grid
                gl = max(0.0, 1 - min(x % grid, grid - x % grid, y % grid, grid - y % grid) / max(0.7, n / 256))
                r += 0.02 * gl; g += 0.10 * gl; b += 0.16 * gl
            r += 0.10 * edge; g += 0.45 * edge; b += 0.55 * edge
            for x1, y1, x2, y2, w in segs:
                vx, vy = x2 - x1, y2 - y1
                u = max(0.0, min(1.0, ((x - x1) * vx + (y - y1) * vy) / (vx * vx + vy * vy)))
                d = math.hypot(x - x1 - u * vx, y - y1 - u * vy)
                k = w * (max(0.0, min(1.0, core - d + 0.5)) + 0.55 * math.exp(-(d / glow) ** 2))
                r += 0.31 * k; g += 0.89 * k; b += 1.0 * k
            for idx, (vxp, vyp, _) in enumerate(pts):   # vertices: one magenta "packet", the rest white-cyan
                d = math.hypot(x - vxp, y - vyp)
                k = math.exp(-(d / max(1.0, n / 34)) ** 2) * 1.3
                if idx == 2:
                    r += 1.0 * k; g += 0.31 * k; b += 0.85 * k
                else:
                    r += 0.8 * k; g += 0.95 * k; b += 1.0 * k
            o = (j * n + i) * 4
            px[o] = int(min(1, r) * 255); px[o + 1] = int(min(1, g) * 255); px[o + 2] = int(min(1, b) * 255); px[o + 3] = int(a * 255)
    return px


def png(n, px):
    raw = b''.join(b'\0' + bytes(px[j * n * 4:(j + 1) * n * 4]) for j in range(n))
    def chunk(t, d): return struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d) & 0xffffffff)
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', n, n, 8, 6, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(raw, 9)) + chunk(b'IEND', b'')


def bmp(n, px):
    rows = b''.join(bytes(b for i in range(n) for b in (px[(j * n + i) * 4 + 2], px[(j * n + i) * 4 + 1], px[(j * n + i) * 4], px[(j * n + i) * 4 + 3])) for j in range(n - 1, -1, -1))
    mask = b'\0' * (((n + 31) // 32) * 4 * n)
    return struct.pack('<IiiHHIIiiII', 40, n, n * 2, 1, 32, 0, len(rows) + len(mask), 0, 0, 0, 0) + rows + mask


sizes = [16, 24, 32, 48, 64, 256]
images = []
for n in sizes:
    px = render(n)
    images.append(png(n, px) if n == 256 else bmp(n, px))
    if n == 256:
        open(os.path.join(HERE, 'matrixsys.png'), 'wb').write(png(n, px))
out = struct.pack('<HHH', 0, 1, len(sizes))
off = 6 + 16 * len(sizes)
for n, d in zip(sizes, images):
    out += struct.pack('<BBBBHHII', n % 256, n % 256, 0, 0, 1, 32, len(d), off)
    off += len(d)
open(os.path.join(HERE, 'matrixsys.ico'), 'wb').write(out + b''.join(images))
print('icon written')
