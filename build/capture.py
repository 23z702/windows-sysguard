"""capture.py - 用 GDI PrintWindow 把界面窗口逐页截图，输出 BMP 便于检查视觉稿"""
import ctypes
import ctypes.wintypes as wt
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "user"))

user32 = ctypes.WinDLL("user32", use_last_error=True)
gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [("biSize", wt.DWORD), ("biWidth", wt.LONG), ("biHeight", wt.LONG),
                ("biPlanes", wt.WORD), ("biBitCount", wt.WORD),
                ("biCompression", wt.DWORD), ("biSizeImage", wt.DWORD),
                ("biXPelsPerMeter", wt.LONG), ("biYPelsPerMeter", wt.LONG),
                ("biClrUsed", wt.DWORD), ("biClrImportant", wt.DWORD)]


def grab(hwnd, path):
    rect = wt.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(rect))
    w = rect.right - rect.left
    h = rect.bottom - rect.top
    if w <= 0 or h <= 0:
        raise RuntimeError("窗口尺寸异常")

    hdc = user32.GetWindowDC(hwnd)
    mdc = gdi32.CreateCompatibleDC(hdc)
    hbmp = gdi32.CreateCompatibleBitmap(hdc, w, h)
    gdi32.SelectObject(mdc, hbmp)

    ok = user32.PrintWindow(hwnd, mdc, 2)  # PW_RENDERFULLCONTENT
    if not ok:
        user32.PrintWindow(hwnd, mdc, 0)

    bi = BITMAPINFOHEADER()
    bi.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bi.biWidth = w
    bi.biHeight = h
    bi.biPlanes = 1
    bi.biBitCount = 24
    bi.biCompression = 0

    stride = ((w * 3 + 3) // 4) * 4
    buf = ctypes.create_string_buffer(stride * h)
    gdi32.GetDIBits(mdc, hbmp, 0, h, buf, ctypes.byref(bi), 0)

    gdi32.DeleteObject(hbmp)
    gdi32.DeleteDC(mdc)
    user32.ReleaseDC(hwnd, hdc)

    with open(path, "wb") as f:
        f.write(b"BM")
        f.write(struct.pack("<IHHI", 14 + 40 + len(buf), 0, 0, 54))
        f.write(bytes(bi))
        f.write(buf.raw)
    return w, h


def main():
    import huorong_gui as hg

    out = os.path.join(HERE, "shots")
    os.makedirs(out, exist_ok=True)

    app = hg.App()
    app.geometry("1060x690+80+60")
    for _ in range(10):
        app.update_idletasks()
        app.update()

    hwnd = user32.GetAncestor(app.winfo_id(), 2)  # GA_ROOT

    for key in ("home", "guard", "proc", "log", "about"):
        app.show(key)
        for _ in range(6):
            app.update_idletasks()
            app.update()
        w, h = grab(hwnd, os.path.join(out, f"{key}.bmp"))
        print(f"{key}: {w}x{h}")

    app.destroy()
    return 0


if __name__ == "__main__":
    # 截图要连着驱动才有「已连接」的状态，非管理员下会拍出"离线"界面
    import os as _os
    import sys as _sys
    _sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "user"))
    import elevate as _elevate
    _rc = _elevate.ensure_admin()
    if _rc is not None:
        sys.exit(_rc)
    sys.exit(_elevate.finish(main()))
