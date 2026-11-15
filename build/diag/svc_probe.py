"""svc_probe.py —— 摸清机器上到底加载了几个 sysguard 实例、各自是什么版本。

背景：v4/v7 能同时驻留（设备名回退机制），而 guard_ctl.Guard() 会优先连
注册表里声明的那个设备名，可能连到旧实例上，表现为「驱动已连接但新功能不生效」。
"""
import ctypes
import sys
import os
from ctypes import wintypes as w

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "user"))

import guard_ctl  # noqa: E402

nt = ctypes.WinDLL("ntdll")


class MODULE(ctypes.Structure):
    _fields_ = [("Section", ctypes.c_void_p), ("MappedBase", ctypes.c_void_p),
                ("ImageBase", ctypes.c_void_p), ("ImageSize", w.ULONG),
                ("Flags", w.ULONG), ("LoadOrderIndex", w.USHORT),
                ("InitOrderIndex", w.USHORT), ("LoadCount", w.USHORT),
                ("OffsetToFileName", w.USHORT), ("FullPathName", ctypes.c_char * 256)]


def loaded_modules():
    size = 0x800000
    buf = ctypes.create_string_buffer(size)
    ret = w.ULONG(0)
    st = nt.NtQuerySystemInformation(11, buf, size, ctypes.byref(ret))
    if st != 0:
        raise OSError(st, "NtQuerySystemInformation 失败")
    n = ctypes.c_ulong.from_buffer(buf).value
    base = ctypes.addressof(buf) + 8
    esz = ctypes.sizeof(MODULE)
    out = []
    for i in range(n):
        m = MODULE.from_address(base + i * esz)
        full = m.FullPathName.decode("latin1")
        nm = full[m.OffsetToFileName:] if m.OffsetToFileName else full
        out.append((m.ImageBase or 0, m.ImageSize, nm))
    return out


def probe_devices():
    rows = []
    for cand in guard_ctl.DEVICE_CANDIDATES:
        try:
            g = guard_ctl.Guard(cand)
        except OSError as e:
            rows.append((cand, None, None, getattr(e, "winerror", "?")))
            continue
        try:
            st = g.query()
            rows.append((cand, st["version"], len(g.list_pids()), 0))
        except OSError as e:
            rows.append((cand, "query失败", str(e), 0))
        finally:
            g.close()
    return rows


def main():
    print("==== 内核里加载的 sysguard / probe ====")
    mods = [m for m in loaded_modules() if "sysguard" in m[2].lower()
            or "probe" in m[2].lower()]
    for b, s, n in mods:
        print("  base=0x%X  size=0x%X  %s" % (b, s, n))
    print("  共 %d 个实例" % len(mods))
    if len(mods) > 1:
        print("  [!] 多实例共存：旧实例会占住一个设备名，新功能可能不生效")

    print()
    print("==== 设备探测 ====")
    for cand, ver, npids, extra in probe_devices():
        if ver is None:
            continue                     # 打不开的不打印，避免噪音
        if isinstance(npids, int):
            print("  %-18s 版本=%-5s 名单=%d 个" % (cand, ver, npids))
        else:
            print("  %-18s %s" % (cand, npids))

    print()
    print("==== Guard() 默认会连到哪个 ====")
    announced = guard_ctl.registered_device_path()
    print("  注册表声明:", announced)
    try:
        g = guard_ctl.Guard()
        print("  实际连接  :", g.path, "版本 =", g.query()["version"])
        g.close()
    except OSError as e:
        print("  连接失败  :", e)
    return 0


if __name__ == "__main__":
    sys.exit(main())
