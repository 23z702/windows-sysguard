"""guard_ctl.py —— sysguard.sys 用户态控制封装（纯 ctypes，无第三方依赖）

对外接口：
    g = Guard()            # 打开 \\\\.\\sysguard
    g.protect(pid)         # 加入保护名单
    g.unprotect(pid)
    g.query()              # -> dict  驱动状态
    g.events()             # -> list[dict] 拦截记录
    g.set_config(...)      # 开关防护项
    g.list_pids()
    g.unload_token()       # 授权卸载（之后 sc stop 才能真正卸载）
"""

import ctypes
import ctypes.wintypes as wt
import os
import re

DEVICE_PATH = r"\\.\sysguard"
# 驱动在 \Device\sysguard 撞名时会自动换后缀，并把真实名字写进注册表；
# 这里优先用注册表里的名字，找不到再按顺序盲试（数字后缀在前，避免碰到残留空壳）
DEVICE_CANDIDATES = ([f"\\\\.\\sysguard{i}" for i in range(1, 10)] + [DEVICE_PATH])

REG_PARAM_KEY = r"SYSTEM\CurrentControlSet\Services\sysguard\Parameters"
# 每次加载都会覆盖的「当前活跃实例」，换服务名并存多个版本时以它为准
REG_ACTIVE_KEY = r"SOFTWARE\SysGuard"


def _to_dos(name):
    prefix = "\\DosDevices\\"
    if isinstance(name, str) and name.upper().startswith(prefix.upper()):
        return "\\\\.\\" + name[len(prefix):]
    return None


def active_device_path():
    """读取驱动每次加载时写入的活跃设备名（优先于按服务名查）"""
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_ACTIVE_KEY) as k:
            name, _ = winreg.QueryValueEx(k, "ActiveDevice")
    except OSError:
        return None
    return _to_dos(name)


def detect_service_name():
    """找出「当前活跃设备」属于哪个服务。

    升级或换名安装后机器上会同时留着旧服务，按名字猜很容易打错目标。
    先把 ActiveDevice 反查各服务的 Parameters\\DeviceName；反查不到再退回
    「内核实际加载的镜像名 ↔ 服务 ImagePath」这一层，见 service_for_loaded_image()。
    """
    import winreg

    base = r"SYSTEM\CurrentControlSet\Services"
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base, 0, winreg.KEY_READ)
    except OSError:
        return None
    try:
        names = [winreg.EnumKey(root, i) for i in range(winreg.QueryInfoKey(root)[0])]
    finally:
        winreg.CloseKey(root)

    found = active_device_path()
    dev = found.split("\\")[-1] if found else None
    if dev:
        want = ("\\DosDevices\\" + dev).upper()
        for name in names:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                    base + "\\" + name + "\\Parameters") as k:
                    dn, _ = winreg.QueryValueEx(k, "DeviceName")
            except OSError:
                continue
            if isinstance(dn, str) and dn.upper() == want:
                return name

    # ActiveDevice 是「最后一个加载的实例」写的。多实例共存时它可能指向一个
    # 已经卸掉的旧实例（设备不存在、服务配置也不全），导致连镜像名都取不到。
    return service_for_loaded_image(names)


def loaded_driver_names():
    """内核里当前加载的 .sys 文件名集合（小写）。"""
    class MODULE(ctypes.Structure):
        _fields_ = [("Section", ctypes.c_void_p), ("MappedBase", ctypes.c_void_p),
                    ("ImageBase", ctypes.c_void_p), ("ImageSize", wt.ULONG),
                    ("Flags", wt.ULONG), ("LoadOrderIndex", wt.USHORT),
                    ("InitOrderIndex", wt.USHORT), ("LoadCount", wt.USHORT),
                    ("OffsetToFileName", wt.USHORT),
                    ("FullPathName", ctypes.c_char * 256)]

    nt = ctypes.WinDLL("ntdll")
    size = 0x800000
    for _ in range(4):
        buf = ctypes.create_string_buffer(size)
        ret = wt.ULONG(0)
        st = nt.NtQuerySystemInformation(11, buf, size, ctypes.byref(ret))
        if st == 0xC0000004:          # STATUS_INFO_LENGTH_MISMATCH
            size *= 2
            continue
        if st != 0:
            return set()
        n = ctypes.c_ulong.from_buffer(buf).value
        base_a = ctypes.addressof(buf) + 8
        esz = ctypes.sizeof(MODULE)
        out = set()
        for i in range(n):
            m = MODULE.from_address(base_a + i * esz)
            full = m.FullPathName.decode("latin1", "replace")
            nm = full[m.OffsetToFileName:] if m.OffsetToFileName else full
            if nm:
                out.add(nm.lower())
        return out
    return set()


def service_for_loaded_image(names=None, keyword="sysguard"):
    """用「内核里真的加载了哪个 .sys」去认服务。

    服务键的 ImagePath 指向的文件名，如果正好是当前加载的模块之一，那这个
    服务就是活跃实例。比 ActiveDevice 可靠：后者会被先后加载的旧实例覆盖。

    只在名称含 keyword 的服务里找 —— 内核里加载着上千个系统驱动，不设范围
    会把 ACPI.sys 之类认成自己的镜像。
    """
    mods = loaded_driver_names()
    if not mods:
        return None
    if names is None:
        import winreg
        try:
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                  r"SYSTEM\CurrentControlSet\Services", 0,
                                  winreg.KEY_READ)
        except OSError:
            return None
        try:
            names = [winreg.EnumKey(root, i)
                     for i in range(winreg.QueryInfoKey(root)[0])]
        finally:
            winreg.CloseKey(root)

    pool = [n for n in names if keyword and keyword in n.lower()] if keyword else names
    for name in pool:
        img = service_image_path(name)
        if not img:
            continue
        fn = img.replace("/", "\\").rsplit("\\", 1)[-1].lower()
        if fn in mods:
            return name
    return None


def registered_device_path():
    """读取驱动自己上报的设备名（\\DosDevices\\xxx -> \\\\.\\xxx）"""
    import winreg
    found = active_device_path()
    if found:
        return found
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PARAM_KEY) as k:
            name, _ = winreg.QueryValueEx(k, "DeviceName")
    except OSError:
        return None
    return _to_dos(name)


def service_image_path(service=None):
    r"""取某个服务实际加载的 .sys 完整路径（\??\C:\...\xxx.sys）。"""
    import winreg
    svc = service or detect_service_name()
    if not svc:
        return None
    base = "SYSTEM" + chr(92) + "CurrentControlSet" + chr(92) + "Services" + chr(92)
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base + svc) as k:
            return winreg.QueryValueEx(k, "ImagePath")[0]
    except OSError:
        return None


def build_tag(image_path=None):
    """从镜像文件名推导「构建号」：sysguard_v4.sys -> v4。

    本工程有两套编号，刻意保留：
      · 驱动版本  1.2  —— 内核里的 GUARD_VERSION，表示行为/接口版本；
      · 构建号    v4   —— 文件迭代号，重新编译一次就加一。
    两者不是一回事（v2/v3 也可能是 1.1），所以界面上同时显示，避免对不上。
    """
    path = image_path if image_path is not None else service_image_path()
    if not path:
        return ""
    base = os.path.basename(path.replace(chr(92) + "??" + chr(92), ""))
    m = re.search(r"_v(\d+)", base, re.I)
    return ("v" + m.group(1)) if m else ""


def version_label(version, build):
    """统一成「1.2（构建 v4）」这种写法，各处显示保持一致。"""
    if not version:
        return build or "未知"
    return f"{version}（构建 {build}）" if build else str(version)

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
FILE_ATTRIBUTE_NORMAL = 0x80

METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0
GUARD_DEVICE_TYPE = 0x8A31

GUARD_UNLOAD_TOKEN = 0x48524744  # 'HRGD'


def _ctl_code(function):
    return (GUARD_DEVICE_TYPE << 16) | (FILE_ANY_ACCESS << 14) | (function << 2) | METHOD_BUFFERED


IOCTL_PROTECT      = _ctl_code(0x800)
IOCTL_UNPROTECT    = _ctl_code(0x801)
IOCTL_QUERY        = _ctl_code(0x802)
IOCTL_GET_EVENTS   = _ctl_code(0x803)
IOCTL_SET_CONFIG   = _ctl_code(0x804)
IOCTL_UNLOAD       = _ctl_code(0x805)
IOCTL_CLEAR_EVENT  = _ctl_code(0x806)
IOCTL_LIST_PIDS    = _ctl_code(0x807)
IOCTL_KILL         = _ctl_code(0x808)

# 强制结束的选项位，与驱动里的 GUARD_KILL_* 一致
KILL_FORCE   = 0x1     # 目标在保护名单里也照杀（驱动会先摘掉保护）
KILL_NO_WAIT = 0x2     # 不等确认退出，下发即返回


class GUARD_CONFIG(ctypes.Structure):
    _fields_ = [
        ("EnableProcess", ctypes.c_ubyte),
        ("EnableThread", ctypes.c_ubyte),
        ("EnableRegistry", ctypes.c_ubyte),
        ("EnableUnload", ctypes.c_ubyte),
    ]


class GUARD_STATE(ctypes.Structure):
    _fields_ = [
        ("Version", ctypes.c_uint32),
        ("ProtectedCount", ctypes.c_uint32),
        ("BlockCount", ctypes.c_uint32),
        ("Loaded", ctypes.c_uint32),
        ("Config", GUARD_CONFIG),
        ("QuietCount", ctypes.c_uint32),
    ]


class GUARD_EVENT(ctypes.Structure):
    _fields_ = [
        ("Time", ctypes.c_int64),
        ("Type", ctypes.c_uint32),
        ("TargetPid", ctypes.c_uint32),
        ("CallerPid", ctypes.c_uint32),
        ("AccessMask", ctypes.c_uint32),
    ]


EVENT_TYPE_NAME = {
    1: "进程句柄",
    2: "线程句柄",
    3: "注册表",
    4: "驱动卸载",
    5: "配置变更",
    6: "强制结束",
}


class GUARD_KILL_REQUEST(ctypes.Structure):
    _fields_ = [
        ("Pid", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
    ]


class GUARD_KILL_RESULT(ctypes.Structure):
    _fields_ = [
        ("Pid", ctypes.c_uint32),
        ("Method", ctypes.c_uint32),     # 1=内核句柄 2=先摘了保护
        ("Status", ctypes.c_int32),      # 真正的 NTSTATUS
        ("Waited", ctypes.c_uint32),     # 1=已确认退出
    ]


# 驱动把真正的 NTSTATUS 放在结果结构里，这里翻译成人话
NTSTATUS_TEXT = {
    0x00000000: "已结束",
    0xC0000001: "失败（目标拒绝终止，通常是受保护进程 PPL）",
    0xC0000008: "句柄无效",
    0xC000000B: "进程不存在（PID 无效，或已经退出）",
    0xC0000022: "拒绝访问（目标在保护名单内；要强杀请加 --force）",
    0xC000000D: "参数无效（不能结束调用者自身，也不能结束 PID 0/4）",
    0xC000010A: "进程正在退出中",
    0xC000009A: "内核资源不足",
    0xC00000BB: "驱动版本过旧，不支持强制结束（需要 1.3+）",
}


def ntstatus_text(code):
    code &= 0xFFFFFFFF
    return NTSTATUS_TEXT.get(code, f"NTSTATUS 0x{code:08X}")

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.CreateFileW.restype = wt.HANDLE
_k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.LPVOID,
                             wt.DWORD, wt.DWORD, wt.HANDLE]
_k32.DeviceIoControl.restype = wt.BOOL
_k32.DeviceIoControl.argtypes = [wt.HANDLE, wt.DWORD, wt.LPVOID, wt.DWORD,
                                 wt.LPVOID, wt.DWORD, ctypes.POINTER(wt.DWORD), wt.LPVOID]
_k32.CloseHandle.restype = wt.BOOL
_k32.CloseHandle.argtypes = [wt.HANDLE]


class GuardError(OSError):
    pass


# 打开设备失败时的错误码释义。设备对象的 DACL 只给 Administrators 全权，
# Everyone 连读都不给，所以「没提权」是最常见的一种失败。
ERROR_HINT = {
    2: "系统找不到指定文件（设备名不存在）",
    3: "路径不存在",
    5: "拒绝访问（当前进程未提升为管理员）",
    32: "设备已被其他进程独占",
    433: "无此设备（驱动未加载，或设备名已换）",
}

# 这些错误只说明「这个候选名字本来就不存在」，不说明真实故障原因，
# 上报时应让位给 5 / 32 这类有信息量的错误。
_NOISE = (2, 3, 433)


def is_admin():
    """当前进程是否已提升为管理员。"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def diagnose():
    """逐个候选试开，返回 [(设备路径, 错误码)]，用于排查「离线」的真实原因。"""
    out = []
    for cand in DEVICE_CANDIDATES:
        h = _k32.CreateFileW(cand, GENERIC_READ | GENERIC_WRITE, 0, None,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
        if h and h != INVALID_HANDLE_VALUE:
            _k32.CloseHandle(h)
            out.append((cand, 0))
        else:
            out.append((cand, ctypes.get_last_error()))
    return out


def _pick_error(attempts):
    """从多次尝试里挑一个最能说明问题的错误。

    历史 bug：旧实现直接取**最后一次**尝试的错误码，而候选列表末位是
    \\\\.\\sysguard（本机通常不存在），于是无论真实原因是权限不足还是被独占，
    用户看到的永远是 433「无此设备」，把真正的 5 完全盖掉。
    """
    for path, err in attempts:
        if err not in _NOISE:
            return path, err
    if attempts:
        return attempts[0]
    return None, 5


class Guard:
    def __init__(self, path=None):
        self.path = None
        self.shadowed = []      # 同时存在、但版本更低的设备：[(路径, 版本号)]
        if path:
            candidates = [path]
        else:
            announced = registered_device_path()
            candidates = ([announced] if announced else []) + \
                         [c for c in DEVICE_CANDIDATES if c != announced]

        attempts, opened = [], []
        for cand in candidates:
            h = _k32.CreateFileW(cand,
                                 GENERIC_READ | GENERIC_WRITE,
                                 0, None, OPEN_EXISTING,
                                 FILE_ATTRIBUTE_NORMAL, None)
            if not h or h == INVALID_HANDLE_VALUE:
                attempts.append((cand, ctypes.get_last_error()))
                continue
            opened.append((self._peek_version(h), h, cand))
            if path:
                break               # 显式点名的设备，只认它

        if not opened:
            _, err = _pick_error(attempts)
            msg = self._explain(err, attempts)
            # 驱动停止后 \DosDevices\sysguard 这类符号链接可能还残留，
            # 此时 CreateFile 返回的是 5（而不是 2），很容易被读成"没提权"。
            # 查一下服务状态，把话说准。
            try:
                import service_ctl as _svc
                _name = detect_service_name()
                _st = _svc.service_state(_name) if _name else None
                if _st is not None and _st != 4:
                    msg += (f"（服务 {_name} 当前是 "
                            f"{_svc.STATE_NAME.get(_st, _st)}，先启动它）")
            except Exception:            # noqa: BLE001 - 只是补一句提示
                pass
            exc = GuardError(err, msg)
            exc.winerror = err       # 方便调用方按错误码分支（OSError 默认不会填）
            raise exc

        # 多实例共存时（旧版本没卸干净），每个实例各占一个设备名。
        # 必须按版本挑最新的：盲信注册表声明的那个名字，会出现
        # 「显示已连接、但新功能一律 ERROR_INVALID_FUNCTION」的怪象。
        opened.sort(key=lambda x: x[0], reverse=True)
        ver, h, cand = opened[0]
        for _, h2, c2 in opened[1:]:
            _k32.CloseHandle(h2)
        self.shadowed = [(c2, v2) for v2, _, c2 in opened[1:]]
        self._h = h
        self.path = cand

    def _peek_version(self, handle):
        """定下最终连接前，先读一次这个句柄背后的驱动版本。

        读不到就返回 0，让它在排序里垫底——但不能因为它读不到就整个放弃，
        早期版本可能没有 QUERY 之外的兼容差异。
        """
        old = getattr(self, "_h", None)
        self._h = handle
        try:
            raw = self._ioctl(IOCTL_QUERY, None, ctypes.sizeof(GUARD_STATE))
            return GUARD_STATE.from_buffer_copy(raw).Version
        except (OSError, ValueError):
            return 0
        finally:
            self._h = old

    @staticmethod
    def _explain(err, attempts):
        hint = ERROR_HINT.get(err, "未知错误")
        head = f"无法打开驱动设备（错误 {err}：{hint}）"
        if err == 5:
            head += "。请以「管理员身份运行」重新启动；驱动设备只授权给管理员。"
        elif err == 32:
            head += "。先关掉其他界面 / 测试进程再试。"
        else:
            head += "。驱动可能未安装或未启动，先跑 build\\install.ps1。"
        tried = "、".join(f"{p.rsplit(chr(92), 1)[-1]}={e}" for p, e in attempts[:3])
        return f"{head}（已尝试 {tried}）"

    def close(self):
        if self._h:
            _k32.CloseHandle(self._h)
            self._h = None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    # -- 底层 --
    def _ioctl(self, code, in_obj=None, out_size=0):
        in_buf, in_len = None, 0
        if in_obj is not None:
            in_buf = ctypes.byref(in_obj)
            in_len = ctypes.sizeof(in_obj)

        out_buf = ctypes.create_string_buffer(max(out_size, 1))
        returned = wt.DWORD(0)
        ok = _k32.DeviceIoControl(self._h, code, in_buf, in_len,
                                  out_buf, out_size, ctypes.byref(returned), None)
        if not ok:
            raise GuardError(ctypes.get_last_error(),
                             f"DeviceIoControl 失败（IOCTL=0x{code:08X}）")
        return out_buf.raw[:returned.value]

    # -- 业务 --
    def protect(self, pid):
        data = self._ioctl(IOCTL_PROTECT, ctypes.c_uint32(pid), 4)
        return ctypes.c_uint32.from_buffer_copy(data).value

    def unprotect(self, pid):
        data = self._ioctl(IOCTL_UNPROTECT, ctypes.c_uint32(pid), 4)
        return ctypes.c_uint32.from_buffer_copy(data).value

    def query(self):
        raw = self._ioctl(IOCTL_QUERY, None, ctypes.sizeof(GUARD_STATE))
        st = GUARD_STATE.from_buffer_copy(raw)
        return {
            "version": f"{st.Version >> 16}.{st.Version & 0xFFFF}",
            "protected": st.ProtectedCount,
            "blocked": st.BlockCount,
            "quiet": st.QuietCount,
            "loaded": bool(st.Loaded),
            "config": {
                "process": bool(st.Config.EnableProcess),
                "thread": bool(st.Config.EnableThread),
                "registry": bool(st.Config.EnableRegistry),
                "unload_lock": bool(st.Config.EnableUnload),
            },
        }

    def events(self, limit=256):
        size = ctypes.sizeof(GUARD_EVENT) * limit
        raw = self._ioctl(IOCTL_GET_EVENTS, None, size)
        n = len(raw) // ctypes.sizeof(GUARD_EVENT)
        out = []
        for i in range(n):
            ev = GUARD_EVENT.from_buffer_copy(raw, i * ctypes.sizeof(GUARD_EVENT))
            out.append({
                "time": ev.Time,
                "type": ev.Type,
                "type_name": EVENT_TYPE_NAME.get(ev.Type, f"未知({ev.Type})"),
                "target_pid": ev.TargetPid,
                "caller_pid": ev.CallerPid,
                "access": ev.AccessMask,
            })
        return out

    def clear_events(self):
        self._ioctl(IOCTL_CLEAR_EVENT, None, 0)

    def set_config(self, process=None, thread=None, registry=None, unload_lock=None):
        cur = self.query()["config"]
        cfg = GUARD_CONFIG()
        cfg.EnableProcess = cur["process"] if process is None else bool(process)
        cfg.EnableThread = cur["thread"] if thread is None else bool(thread)
        cfg.EnableRegistry = cur["registry"] if registry is None else bool(registry)
        cfg.EnableUnload = cur["unload_lock"] if unload_lock is None else bool(unload_lock)
        self._ioctl(IOCTL_SET_CONFIG, cfg, 0)

    def list_pids(self):
        limit = 128
        raw = self._ioctl(IOCTL_LIST_PIDS, None, 4 * limit)
        return [ctypes.c_uint32.from_buffer_copy(raw, i * 4).value
                for i in range(len(raw) // 4)]

    def kill(self, pid, force=False, wait=True):
        """驱动级强制结束进程。

        和 TerminateProcess 的区别：目标把自己 DACL 改成「谁都进不来」时，
        用户态连 PROCESS_TERMINATE 句柄都开不出来（返回 5）；这里由内核发起
        ZwOpenProcess，不用过访问检查。

        返回 dict：ok / status / text / waited / method / pid
        """
        flags = (KILL_FORCE if force else 0) | (0 if wait else KILL_NO_WAIT)
        raw = self._ioctl(IOCTL_KILL,
                          GUARD_KILL_REQUEST(int(pid), flags),
                          ctypes.sizeof(GUARD_KILL_RESULT))
        if len(raw) < ctypes.sizeof(GUARD_KILL_RESULT):
            raise GuardError(0, "驱动返回的数据长度不足，可能版本不匹配")
        res = GUARD_KILL_RESULT.from_buffer_copy(raw)
        status = res.Status & 0xFFFFFFFF
        return {
            "pid": res.Pid,
            "ok": status == 0,
            "status": status,
            "text": ntstatus_text(status),
            "waited": bool(res.Waited),
            "method": res.Method,
        }

    def unload_token(self):
        """发送卸载令牌：之后 sc stop 才能真正卸载驱动（测试完成后的逃生门）"""
        self._ioctl(IOCTL_UNLOAD, ctypes.c_uint32(GUARD_UNLOAD_TOKEN), 0)
        return True


def is_installed():
    try:
        Guard().close()
        return True
    except OSError:
        return False


# ---------------- 按进程名找 PID ----------------

TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD),
                ("cntUsage", wt.DWORD),
                ("th32ProcessID", wt.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", wt.DWORD),
                ("cntThreads", wt.DWORD),
                ("th32ParentProcessID", wt.DWORD),
                ("pcPriClassBase", wt.LONG),
                ("dwFlags", wt.DWORD),
                ("szExeFile", wt.WCHAR * 260)]


def pids_by_name(name):
    """按可执行文件名找 PID（大小写无关，可省略 .exe）。

    用 Toolhelp 快照而不是 WMI：快、无依赖，而且不需要额外权限。
    """
    want = name.lower()
    if not want.endswith(".exe"):
        want += ".exe"

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
    k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
    k32.Process32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
    k32.Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]

    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == INVALID_HANDLE_VALUE:
        return []

    found = []
    entry = _PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
    ok = k32.Process32FirstW(snap, ctypes.byref(entry))
    while ok:
        exe = entry.szExeFile.lower()
        if exe == want or exe.rsplit("\\", 1)[-1] == want:
            found.append(entry.th32ProcessID)
        ok = k32.Process32NextW(snap, ctypes.byref(entry))
    k32.CloseHandle(snap)
    return found


if __name__ == "__main__":
    # 直接跑本文件时先自动提权；作为模块被 import 时不受影响
    try:
        from . import elevate as _elev
    except ImportError:
        import elevate as _elev
    _rc = _elev.ensure_admin()
    if _rc is not None:
        raise SystemExit(_rc)

    if not is_installed():
        print("驱动设备打不开，逐个候选试开结果：")
        for p, e in diagnose():
            detail = "OK" if e == 0 else f"err={e} {ERROR_HINT.get(e, '未知')}"
            print(f"  {p:<16} {detail}")
        print(f"当前进程管理员: {is_admin()}")
        print("若看到 err=5，说明只是没提权：用管理员身份重开终端即可，驱动本身是好的。")
        raise SystemExit(_elev.finish(1))

    import argparse
    ap = argparse.ArgumentParser(description="sysguard 驱动控制台")
    ap.add_argument("action", nargs="?", default="status",
                    choices=["status", "kill"], help="默认 status")
    ap.add_argument("pid", nargs="?", type=int, help="kill 时的目标 PID")
    ap.add_argument("--force", action="store_true",
                    help="目标即使在本保护名单里也强制结束（会先摘掉保护）")
    ap.add_argument("--no-wait", action="store_true",
                    help="不等待确认退出，下发后立即返回")
    ap.add_argument("--name", help="kill 时按可执行文件名匹配，如 notepad.exe（可省略 .exe）")
    args = ap.parse_args()

    if args.action == "kill":
        targets = []
        if args.pid:
            targets.append(args.pid)
        if args.name:
            matched = pids_by_name(args.name)
            if not matched:
                print(f"没找到名为 {args.name} 的进程")
                raise SystemExit(_elev.finish(2))
            targets.extend(p for p in matched if p not in targets)

        if not targets:
            print(r"用法: python user\guard_ctl.py kill <PID> [--force] [--no-wait]")
            print(r"      python user\guard_ctl.py kill --name notepad.exe [--force]")
            raise SystemExit(_elev.finish(2))

        with Guard() as g:
            # 单个目标给出完整细节；多个目标只报一行一个，最后汇总
            if len(targets) == 1:
                try:
                    r = g.kill(targets[0], force=args.force, wait=not args.no_wait)
                except OSError as e:
                    print(f"强制结束失败: {e}")
                    raise SystemExit(_elev.finish(1))
                mark = "OK" if r["ok"] else "FAIL"
                print(f"[{mark}] PID {r['pid']}  status=0x{r['status']:08X}  {r['text']}")
                print(f"       方式: {'内核句柄' if r['method'] & 1 else '普通'}"
                      f"{' + 先摘除保护' if r['method'] & 2 else ''}"
                      f"，确认退出: {'是' if r['waited'] else '否'}")
                raise SystemExit(_elev.finish(0 if r["ok"] else 1))

            print(f"共 {len(targets)} 个目标，逐个下发：")
            done = 0
            for pid in targets:
                try:
                    r = g.kill(pid, force=args.force, wait=not args.no_wait)
                except OSError as e:
                    print(f"  [FAIL] {pid:<7} {e}")
                    continue
                if r["ok"]:
                    done += 1
                print(f"  [{'OK' if r['ok'] else 'FAIL'}] {pid:<7} "
                      f"status=0x{r['status']:08X}  {r['text']}")
            print(f"合计：成功 {done} / 失败 {len(targets) - done}")
        raise SystemExit(_elev.finish(0 if done == len(targets) else 1))

    with Guard() as g:
        st = g.query()
        img = service_image_path()
        print(f"驱动版本   : {version_label(st['version'], build_tag(img))}")
        print(f"驱动文件   : {img}")
        print(f"服务名     : {detect_service_name()}")
        print(f"受保护进程 : {st['protected']}")
        print(f"累计拦截   : {st['blocked']}")
        print(f"防护开关   : {st['config']}")
        print(f"保护名单   : {g.list_pids()}")
        print(f"当前进程PID: {os.getpid()}")

    _elev.finish(0)
