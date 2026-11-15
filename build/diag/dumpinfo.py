r"""蓝屏转储速查：一条命令拿到 BugCheck 号、参数、出错指令和归属模块。

用法:
    python build\diag\dumpinfo.py                    # 分析最新一个 dump
    python build\diag\dumpinfo.py <path.dmp>         # 分析指定 dump
    python build\diag\dumpinfo.py <path.dmp> --asm   # 额外反汇编出错指令附近

为什么不自己解析: Windows 写出来的内核转储是 PAGEDU64 头（不是 minidump 的
MDMP），模块表、物理内存描述符、上下文记录全都依赖虚拟地址翻译，自己啃
成本很高。本机装了 WDK 就自带 kd.exe，直接调它最省事 —— 而且没有符号也能
拿到 BugCheck 参数和「出错指令属于哪个模块 + 模块内偏移」，足够定位。

本机 kd.exe 的常见位置:
    C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe
"""
import glob
import os
import re
import subprocess
import sys

KD_CANDIDATES = [
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe",
    r"C:\Program Files\Windows Kits\10\Debuggers\x64\kd.exe",
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\kd.exe",
]

BUGCHECK_NAME = {
    "a": "IRQL_NOT_LESS_OR_EQUAL —— 在过高的 IRQL 访问了无效/可分页地址",
    "d1": "DRIVER_IRQL_NOT_LESS_OR_EQUAL —— 驱动在过高 IRQL 访问了错误地址",
    "3b": "SYSTEM_SERVICE_EXCEPTION",
    "50": "PAGE_FAULT_IN_NONPAGED_AREA —— 访问了不可换出的无效地址",
    "c2": "BAD_POOL_CALLER —— 内存池使用错误（重复释放/野指针）",
    "c1": "SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION",
    "c4": "DRIVER_VERIFIER_DETECTED_VIOLATION",
    "c5": "DRIVER_CORRUPTED_EXPOOL",
    "1e": "KMODE_EXCEPTION_NOT_HANDLED",
    "7e": "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
    "109": "CRITICAL_STRUCTURE_CORRUPTION —— PatchGuard 抓到内核结构被改",
    "139": "KERNEL_SECURITY_CHECK_FAILURE",
}


def find_kd():
    for p in KD_CANDIDATES:
        if os.path.isfile(p):
            return p
    hit = glob.glob(r"C:\Program Files (x86)\Windows Kits\*\Debuggers\x64\kd.exe")
    return hit[0] if hit else None


def newest_dump():
    dumps = glob.glob(r"C:\Windows\Minidump\*.dmp")
    if os.path.isfile(r"C:\Windows\MEMORY.DMP"):
        dumps.append(r"C:\Windows\MEMORY.DMP")
    if not dumps:
        return None
    return max(dumps, key=os.path.getmtime)


def run_kd(kd, dump, commands):
    cmd = [kd, "-z", dump, "-y", r"C:\symbols_none", "-c", commands + ";q"]
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=180)
    except subprocess.TimeoutExpired:
        return ""
    text = out.stdout.decode("utf-8", errors="replace")
    if len(text) < 200:
        text = out.stdout.decode("mbcs", errors="replace")
    return text


def parse(text):
    info = {}

    m = re.search(r"BUGCHECK_CODE:\s+([0-9a-fA-F]+)", text)
    if m:
        info["code"] = m.group(1).lower()
    for i in (1, 2, 3, 4):
        m = re.search(r"BUGCHECK_P%d:\s+([0-9a-fA-F`]+)" % i, text)
        if m:
            info["p%d" % i] = m.group(1).replace("`", "")

    m = re.search(r"FAULTING_MODULE:\s+([0-9a-fA-F`]+)\s+(\S+)", text)
    if m:
        info["fault_base"] = m.group(1).replace("`", "")
        info["fault_mod"] = m.group(2)

    # 模块列表里挑出非微软的（名字里带 sysguard/probe，或我们自己编的）。
    # kd 的 lm 输出分两段：先是当前已加载，后面 "Unloaded modules:" 是历史镜像。
    # 两段必须分开统计，否则会把早就卸掉的旧构建误判成"崩溃时正在运行"。
    loaded, unloaded = [], []
    in_unloaded = False
    for line in text.splitlines():
        if "Unloaded modules:" in line:
            in_unloaded = True
            continue
        mm = re.match(r"^\s*([0-9a-f`]{8,})\s+([0-9a-f`]{8,})\s+(\S+)", line)
        if mm:
            name = mm.group(3)
            if re.search(r"sysguard|probe|sgprobe", name, re.I):
                bucket = unloaded if in_unloaded else loaded
                bucket.append((mm.group(1).replace("`", ""),
                               mm.group(2).replace("`", ""), name))
    info["our_mods"] = loaded
    info["unloaded_mods"] = unloaded
    return info


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    want_asm = "--asm" in sys.argv

    dump = args[0] if args else newest_dump()
    if not dump:
        print("没找到任何 dump 文件（C:\\Windows\\Minidump 为空）")
        return 1
    if not os.path.isfile(dump):
        print("dump 不存在:", dump)
        return 1

    kd = find_kd()
    if not kd:
        print("没找到 kd.exe。装了 WDK/SDK 的 Debugging Tools 才有。")
        print("临时办法: 直接在 kd/WinDbg 里打开", dump, "然后 !analyze -v")
        return 1

    import datetime
    ts = datetime.datetime.fromtimestamp(os.path.getmtime(dump))
    print("dump      :", dump)
    print("生成时间  :", ts.strftime("%Y-%m-%d %H:%M:%S"))
    print("大小      : %,d 字节".replace("%,d", format(os.path.getsize(dump), ",")) if False
          else "大小      : {:,} 字节".format(os.path.getsize(dump)))
    print("调试器    :", kd)

    text = run_kd(kd, dump, "!analyze -v;lm")
    if not text:
        print("kd 执行失败或超时")
        return 1

    info = parse(text)

    print("\n===== BugCheck =====")
    code = info.get("code", "?")
    print("代码 : 0x%s  %s" % (code, BUGCHECK_NAME.get(code, "")))
    for i in (1, 2, 3, 4):
        if "p%d" % i in info:
            print("参数%d: 0x%s" % (i, info["p%d" % i]))

    p2 = info.get("p2")
    if p2:
        irql = int(p2, 16)
        names = {0: "PASSIVE_LEVEL", 1: "APC_LEVEL", 2: "DISPATCH_LEVEL"}
        print("IRQL : %d (%s)" % (irql, names.get(irql, "高 IRQL")))

    p3 = info.get("p3")
    if p3 is not None:
        print("访问 : %s" % ("写" if int(p3, 16) == 1 else "读"))

    if "p4" in info and "fault_base" in info:
        ip = int(info["p4"], 16)
        base = int(info["fault_base"], 16)
        print("出错指令: 0x%016X  = %s+0x%X" % (ip, info["fault_mod"], ip - base))

    print("\n===== 崩溃时已加载的 sysguard / probe =====")
    if info["our_mods"]:
        for b, e, n in info["our_mods"]:
            print("  0x%s - 0x%s  %s" % (b, e, n))
    else:
        print("  崩溃时这些驱动均未加载")

    if info["unloaded_mods"]:
        print("\n===== 历史加载过、崩溃前已卸载的 =====")
        for b, e, n in info["unloaded_mods"]:
            print("  0x%s - 0x%s  %s" % (b, e, n))

    if want_asm and "p4" in info:
        print("\n===== 出错指令反汇编 =====")
        addr = "0x" + info["p4"]
        dis = run_kd(kd, dump, "u %s L 12" % addr)
        started = False
        for line in dis.splitlines():
            if re.match(r"^\S*[0-9a-f]{8}`[0-9a-f]{8}\s", line) or re.match(r"^[0-9a-f`]{16}\s", line):
                started = True
            if started:
                print("  " + line.rstrip())
    return 0


if __name__ == "__main__":
    sys.exit(main())
