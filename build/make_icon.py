"""make_icon.py —— 生成「盾守 / SysGuard」的应用图标（零依赖，不需要 Pillow）

产物：
    user/sysguard.ico     多尺寸 ICO（16/32/48/64/128/256），给窗口与任务栏用
    user/logo_128.png     关于页的大 logo（tk 8.6 的 PhotoImage 直接能读）

做法：先在 2 倍分辨率下逐像素画（距离场 + 扫描线），再盒式降采样，
边缘自然带抗锯齿。整个过程只用到 zlib / struct，换台机器也能重跑。

用法：
    python build/make_icon.py            # 重新生成
    python build/make_icon.py --preview  # 顺带导出一张 256 的 PNG 方便肉眼检查
"""

import math
import os
import struct
import sys
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USER = os.path.join(ROOT, "user")

SIZES = [256, 128, 64, 48, 32, 16]
SS = 2                      # 超采样倍数

# 品牌绿：与界面里的 C["green"] 同源
G_TOP = (56, 196, 106)      # #38C46A
G_BOT = (23, 138, 62)       # #178A3E
CHECK = (27, 158, 75)       # #1B9E4B
WHITE = (255, 255, 255)


# ---------------- 几何（全部以 256 为基准） ----------------
SHIELD_TOP, SHIELD_SHOULDER, SHIELD_TIP = 50.0, 140.0, 208.0
SHIELD_HALF = 62.0                      # 侧边竖直段半宽
SHIELD_CORNER = 10.0                    # 顶部圆角


def _bezier_table():
    """底部收尖段：二次贝塞尔 (62,140)->(62,182)->(128,208) 的采样表。"""
    ys, hs = [], []
    for i in range(801):
        t = i / 800.0
        u = 1.0 - t
        x = u * u * 62.0 + 2 * t * u * 62.0 + t * t * 128.0
        y = u * u * 140.0 + 2 * t * u * 182.0 + t * t * 208.0
        ys.append(y)
        hs.append(128.0 - x)
    return ys, hs


_BZ_Y, _BZ_H = _bezier_table()


def shield_half_width(y):
    """盾牌在高度 y 处的半宽；返回 -1 表示不在盾内。"""
    if y < SHIELD_TOP or y > SHIELD_TIP:
        return -1.0
    if y < SHIELD_SHOULDER:
        half = SHIELD_HALF
        if y < SHIELD_TOP + SHIELD_CORNER:            # 顶部两角圆角
            dy = (SHIELD_TOP + SHIELD_CORNER) - y
            r = SHIELD_CORNER
            half -= (r - math.sqrt(max(r * r - dy * dy, 0.0)))
        return half

    # 查表线性插值（表按 y 递增）
    lo, hi = 0, len(_BZ_Y) - 1
    while lo < hi - 1:
        mid = (lo + hi) // 2
        if _BZ_Y[mid] <= y:
            lo = mid
        else:
            hi = mid
    y0, y1 = _BZ_Y[lo], _BZ_Y[hi]
    h0, h1 = _BZ_H[lo], _BZ_H[hi]
    if y1 - y0 < 1e-9:
        return h0
    k = (y - y0) / (y1 - y0)
    k = 0.0 if k < 0.0 else (1.0 if k > 1.0 else k)
    return h0 + (h1 - h0) * k


def seg_dist(px, py, ax, ay, bx, by):
    """点到线段的距离。"""
    dx, dy = bx - ax, by - ay
    L2 = dx * dx + dy * dy
    if L2 <= 1e-9:
        return math.hypot(px - ax, py - ay)
    t = ((px - ax) * dx + (py - ay) * dy) / L2
    t = 0.0 if t < 0.0 else (1.0 if t > 1.0 else t)
    return math.hypot(px - (ax + t * dx), py - (ay + t * dy))


# ---------------- 光栅化 ----------------
def render(master=256, simple=False, ss=None):
    """simple=True 用于 16px 这种极小尺寸：去掉盾牌，只留加粗白勾，
    否则缩小后盾牌轮廓和勾糊成一团，什么都认不出来。"""
    ss = ss or SS
    N = master * ss
    buf = bytearray(N * N * 4)

    cx = cy = N / 2.0
    radius = N / 2.0 - 2.0 * ss                  # 留一点边，避免被裁
    shield_scale = N / 256.0

    for y in range(N):
        fy = y + 0.5
        for x in range(N):
            fx = x + 0.5
            i = (y * N + x) * 4

            # 圆底：渐变 + 抗锯齿边缘
            d = math.hypot(fx - cx, fy - cy)
            edge = radius - d
            if edge <= -1.0:
                continue                          # 完全透明
            a = 1.0 if edge >= 1.0 else (edge + 1.0) / 2.0
            t = (fy - (cy - radius)) / (2.0 * radius)
            t = 0.0 if t < 0.0 else (1.0 if t > 1.0 else t)
            r = G_TOP[0] + (G_BOT[0] - G_TOP[0]) * t
            g = G_TOP[1] + (G_BOT[1] - G_TOP[1]) * t
            b = G_TOP[2] + (G_BOT[2] - G_TOP[2]) * t

            # 左上高光：让圆形不那么平
            hx, hy = cx - radius * 0.42, cy - radius * 0.5
            hd = math.hypot(fx - hx, fy - hy)
            hw = radius * 0.62
            if hd < hw:
                k = (1.0 - hd / hw) ** 2 * 0.20
                r += (255 - r) * k
                g += (255 - g) * k
                b += (255 - b) * k

            # 统一换到 256 基准坐标系里算，别混着两套比例
            ux = fx / shield_scale
            uy = fy / shield_scale

            if simple:
                dd = min(seg_dist(ux, uy, 92, 120, 118, 146),
                         seg_dist(ux, uy, 118, 146, 168, 92))
                if dd <= 24.0:
                    r = g = b = 255.0
            else:
                hw2 = shield_half_width(uy)
                if hw2 > 0 and abs(ux - 128.0) <= hw2:
                    r = g = b = 255.0

                    # 对勾：两段粗线的并集
                    dd = min(seg_dist(ux, uy, 104, 126, 122, 146),
                             seg_dist(ux, uy, 122, 146, 158, 104))
                    if dd <= 8.0:
                        r, g, b = float(CHECK[0]), float(CHECK[1]), float(CHECK[2])

            buf[i] = int(r)
            buf[i + 1] = int(g)
            buf[i + 2] = int(b)
            buf[i + 3] = int(a * 255)

    return downscale(buf, N, N, master, master)


def downscale(buf, w, h, dw, dh):
    """盒式降采样（alpha 加权，避免边缘发黑）。"""
    out = bytearray(dw * dh * 4)
    sx = w / dw
    sy = h / dh
    for oy in range(dh):
        y0 = int(oy * sy)
        y1 = max(y0 + 1, int((oy + 1) * sy))
        for ox in range(dw):
            x0 = int(ox * sx)
            x1 = max(x0 + 1, int((ox + 1) * sx))
            rs = gs = bs = as_ = 0.0
            n = 0
            for y in range(y0, min(y1, h)):
                base = y * w
                for x in range(x0, min(x1, w)):
                    i = (base + x) * 4
                    a = buf[i + 3] / 255.0
                    rs += buf[i] * a
                    gs += buf[i + 1] * a
                    bs += buf[i + 2] * a
                    as_ += a
                    n += 1
            j = (oy * dw + ox) * 4
            if n == 0 or as_ <= 1e-6:
                continue
            out[j] = min(255, int(rs / as_))
            out[j + 1] = min(255, int(gs / as_))
            out[j + 2] = min(255, int(bs / as_))
            out[j + 3] = min(255, int(as_ / n * 255))
    return out


# ---------------- 编码 ----------------
def png_bytes(w, h, rgba):
    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    raw = bytearray()
    for y in range(h):
        raw.append(0)                                   # filter: none
        raw += rgba[y * w * 4:(y + 1) * w * 4]
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b""))


def ico_bytes(images):
    """images: [(size, png_bytes)]，PNG 内嵌式 ICO（Vista+ 支持，tk 也认）。"""
    n = len(images)
    header = struct.pack("<HHH", 0, 1, n)
    offset = 6 + 16 * n
    dirs = b""
    data = b""
    for size, png in images:
        w = 0 if size >= 256 else size
        dirs += struct.pack("<BBBBHHII", w, w, 0, 0, 1, 32, len(png), offset + len(data))
        data += png
    return header + dirs + data


def main():
    if not os.path.isdir(USER):
        print("找不到 user 目录：%s" % USER)
        return 1

    print("渲染 256x256 母版（%dx%d 超采样）…" % (256 * SS, 256 * SS))
    master = render(256)

    images = []
    for size in SIZES:
        if size <= 16:
            rgba = render(size, simple=True, ss=8)      # 极小尺寸单独渲染
        elif size == 256:
            rgba = master
        else:
            rgba = downscale(master, 256, 256, size, size)
        images.append((size, png_bytes(size, size, rgba)))
        print("  %3d x %3d  %5d bytes" % (size, size, len(images[-1][1])))

    ico_path = os.path.join(USER, "sysguard.ico")
    with open(ico_path, "wb") as f:
        f.write(ico_bytes(images))
    print("已写出 %s（%d 字节）" % (ico_path, os.path.getsize(ico_path)))

    # 界面用的两张：关于页 96、顶栏 40。直接按目标尺寸渲染，比缩放清楚。
    for size, name in ((96, "logo_96.png"), (40, "logo_40.png"), (128, "logo_128.png")):
        rgba = downscale(master, 256, 256, size, size)
        p = os.path.join(USER, name)
        with open(p, "wb") as f:
            f.write(png_bytes(size, size, rgba))
        print("已写出 %s（%d 字节）" % (p, os.path.getsize(p)))

    if "--preview" in sys.argv:
        p = os.path.join(ROOT, "build", "diag", "icon_256.png")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(dict((s, d) for s, d in images)[256])
        print("预览：%s" % p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
