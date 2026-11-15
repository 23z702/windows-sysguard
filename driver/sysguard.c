/*
 * sysguard.c  ——  仿火绒自我保护内核驱动
 *
 * 功能：
 *   1. ObRegisterCallbacks 拦截进程/线程句柄创建与复制，
 *      对被保护进程剥离 TERMINATE / VM_WRITE / CREATE_THREAD 等危险权限
 *      —— 效果等同火绒"自我保护"，任务管理器 / taskkill / 强杀工具全部失效
 *   2. 注册表回调锁死自身服务键，禁止 sc delete / 改 ImagePath
 *   3. DriverUnload 拒绝卸载，只有携带令牌的 IOCTL 才放行
 *   4. 拦截事件环形缓冲区，供用户态界面展示"拦截日志"
 *   5. 驱动级强制结束进程：内核态拿 PROCESS_TERMINATE 句柄再 ZwTerminateProcess，
 *      不受目标 DACL 限制（用户态 TerminateProcess 会被 DACL 挡住，这里不会）
 *
 * 编译：见 build/build.sh
 */

#include <ntddk.h>
#include <ntstrsafe.h>

#pragma warning(disable:4996)   /* ExAllocatePoolWithTag 已弃用，但兼容性最好 */

/* 内核头文件不总是带出这些访问掩码，按 ABI 常量补齐 */
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE               0x0001
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD           0x0002
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION            0x0008
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ                 0x0010
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE                0x0020
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME          0x0800
#endif
#ifndef PROCESS_SET_QUOTA
#define PROCESS_SET_QUOTA               0x0100
#endif
#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION         0x0200
#endif
#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE                0x0001
#endif
#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME           0x0002
#endif
#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT              0x0010
#endif
#ifndef THREAD_SET_INFORMATION
#define THREAD_SET_INFORMATION          0x0020
#endif
#ifndef THREAD_SET_LIMITED_INFORMATION
#define THREAD_SET_LIMITED_INFORMATION  0x0400
#endif
#ifndef THREAD_SET_THREAD_TOKEN
#define THREAD_SET_THREAD_TOKEN         0x0080
#endif
#ifndef THREAD_IMPERSONATE
#define THREAD_IMPERSONATE              0x0100
#endif
#ifndef THREAD_DIRECT_IMPERSONATION
#define THREAD_DIRECT_IMPERSONATION     0x0200
#endif
#ifndef WRITE_DAC
#define WRITE_DAC                       0x00040000L
#endif
#ifndef WRITE_OWNER
#define WRITE_OWNER                     0x00080000L
#endif

/* ---------------- 句柄权限裁剪的两档策略 ----------------

   一档「核心」：直接构成「结束进程 / 往目标里塞代码」的能力，裁掉并记录事件。
   一档「静默」：高频、低危（读内存、改优先级、改安全描述符、调试器改线程上下文…），
                同样裁掉，但不写事件、不计入「累计拦截」。

   为什么必须分开：VM_READ(0x10) 和 THREAD_SET_CONTEXT(0x10) 会被任务管理器、
   杀软扫描、调试器、UWP 宿主反复请求，一次扫描就能刷出几十条日志 —— 真实攻击
   反而被淹没，拦截计数也会虚高到没有参考价值。

   两档都不碰 PROCESS_QUERY_* / THREAD_QUERY_*，否则连「查看进程」都会失败。 */

#define GUARD_PROC_CORE   (PROCESS_TERMINATE | PROCESS_CREATE_THREAD | \
                           PROCESS_VM_WRITE | PROCESS_VM_OPERATION | \
                           PROCESS_SUSPEND_RESUME)
#define GUARD_PROC_QUIET  (PROCESS_VM_READ | PROCESS_SET_INFORMATION | \
                           PROCESS_SET_QUOTA | WRITE_DAC | WRITE_OWNER)
#define GUARD_THREAD_CORE (THREAD_TERMINATE | THREAD_SUSPEND_RESUME | \
                           THREAD_SET_THREAD_TOKEN | THREAD_IMPERSONATE | \
                           THREAD_DIRECT_IMPERSONATION)
#define GUARD_THREAD_QUIET (THREAD_SET_CONTEXT | THREAD_SET_INFORMATION | \
                            THREAD_SET_LIMITED_INFORMATION | WRITE_DAC | WRITE_OWNER)

#define GUARD_DEVICE_NAME   L"\\Device\\sysguard"
#define GUARD_SYMLINK_NAME  L"\\DosDevices\\sysguard"
#define GUARD_DOS_NAME      L"\\\\.\\sysguard"

/* 默认服务键（仅在 RegistryPath 缺失时兜底）。实际路径由 DriverEntry 收到
   的 RegistryPath 决定，见 GuardInitPaths —— 这样换任何服务名都能自保护。 */
#define GUARD_SERVICE_KEY   L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\sysguard"

#define GUARD_VERSION       0x00010005   /* 1.5：修复强杀等待用错 API（KeWaitForSingleObject 收到句柄 → 0xA） */
#define GUARD_MAX_PROTECT   128
#define GUARD_MAX_EVENTS    256
#define GUARD_TAG           'dGsS'

/* IOCTL 号，必须与 user/guard_ctl.py 保持一致 */
#define GUARD_DEVICE_TYPE   0x8A31
#define IOCTL_GUARD_PROTECT     CTL_CODE(GUARD_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GUARD_UNPROTECT   CTL_CODE(GUARD_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GUARD_QUERY       CTL_CODE(GUARD_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GUARD_GET_EVENTS  CTL_CODE(GUARD_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GUARD_SET_CONFIG  CTL_CODE(GUARD_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GUARD_UNLOAD      CTL_CODE(GUARD_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GUARD_CLEAR_EVENT CTL_CODE(GUARD_DEVICE_TYPE, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GUARD_LIST_PIDS   CTL_CODE(GUARD_DEVICE_TYPE, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GUARD_KILL        CTL_CODE(GUARD_DEVICE_TYPE, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define GUARD_UNLOAD_TOKEN  0x48524744  /* 'HRGD' */

typedef struct _GUARD_CONFIG {
    UCHAR EnableProcess;
    UCHAR EnableThread;
    UCHAR EnableRegistry;
    UCHAR EnableUnload;
} GUARD_CONFIG;

typedef struct _GUARD_STATE {
    ULONG Version;
    ULONG ProtectedCount;
    ULONG BlockCount;      /* 核心拦截（有事件记录） */
    ULONG Loaded;
    GUARD_CONFIG Config;
    ULONG QuietCount;      /* 低危权限静默裁剪（只计数，不记录） */
} GUARD_STATE;

typedef struct _GUARD_EVENT {
    LARGE_INTEGER Time;
    ULONG Type;        /* 1=进程 2=线程 3=注册表 4=卸载 5=配置 */
    ULONG TargetPid;
    ULONG CallerPid;
    ULONG AccessMask;
} GUARD_EVENT;

typedef struct _GUARD_PROTECT_ENTRY {
    LIST_ENTRY ListEntry;
    HANDLE Pid;
} GUARD_PROTECT_ENTRY, *PGUARD_PROTECT_ENTRY;

/* ---------------- 驱动级强制结束进程 ----------------

   为什么用户态 TerminateProcess 不够：它要先 OpenProcess(PROCESS_TERMINATE)，
   能不能开取决于目标的 DACL 和调用者令牌。目标进程可以把自己的安全描述符
   改成「只留 SYSTEM」甚至空 DACL，普通管理员也开不了句柄 —— 这类进程在任务
   管理器里就是"杀不掉"。

   驱动走的是内核路径：ZwOpenProcess 从内核发起时 PreviousMode = KernelMode，
   对象管理器跳过整个访问检查，不看 DACL；再带上 OBJ_KERNEL_HANDLE，句柄也不
   会进入调用者的句柄表。所以只要进程还活着，就有 TERMINATE 句柄可用。

   边界：Protected Process Light（PPL，如 csrss / MsMpEng）由内核单独校验，
   这种目标会明确失败并回传 NTSTATUS，不做绕过尝试。                        */

#define GUARD_KILL_FORCE      0x00000001   /* 目标在保护名单里也照杀（先摘保护） */
#define GUARD_KILL_NO_WAIT    0x00000002   /* 不等进程真正退出，下发即返回 */

#define GUARD_KILL_M_KERNEL   0x00000001   /* 用内核句柄打开（记录用了哪条路径） */
#define GUARD_KILL_M_UNPROTECT 0x00000002  /* 先摘掉了保护名单条目 */

#define GUARD_KILL_WAIT_MS    5000         /* 等退出的上限，超时不代表没杀掉 */

typedef struct _GUARD_KILL_REQUEST {
    ULONG Pid;
    ULONG Flags;
} GUARD_KILL_REQUEST, *PGUARD_KILL_REQUEST;

typedef struct _GUARD_KILL_RESULT {
    ULONG Pid;        /* 回显，便于批量调用时对齐 */
    ULONG Method;     /* GUARD_KILL_M_* 位组合 */
    LONG  Status;     /* 真正的 NTSTATUS：0 成功，0xC0000022 拒绝，0xC000000B 无此进程 */
    ULONG Waited;     /* 1 = 已确认退出；0 = 下发成功但没等到（或 NO_WAIT） */
} GUARD_KILL_RESULT, *PGUARD_KILL_RESULT;


/* ---------------- 全局状态 ---------------- */

static PDEVICE_OBJECT      g_DeviceObject = NULL;
static PDRIVER_OBJECT      g_DriverObject = NULL;
static PVOID               g_ObProcessCookie = NULL;
static PVOID               g_ObThreadCookie = NULL;
static PVOID               g_RegCookie = NULL;
static PVOID               g_ServiceKeyObject = NULL;
static LARGE_INTEGER       g_RegCookieValue;
static BOOLEAN             g_RegRegistered = FALSE;

/* 自身服务键路径（来自 RegistryPath）与它的 Parameters 子键；
   g_ServiceSuffix 是大写的 "\SERVICES\<服务名>"，用于回调里做后缀比对。 */
static WCHAR               g_ServiceKeyBuf[256];
static UNICODE_STRING      g_ServiceKeyPath;
static WCHAR               g_ParamKeyBuf[300];
static UNICODE_STRING      g_ParamKeyPath;
static WCHAR               g_ServiceSuffix[128];
static LIST_ENTRY          g_ProtectList;
static KSPIN_LOCK          g_ListLock;
static LONG                g_ProtectedCount = 0;

static GUARD_CONFIG        g_Config;
static LONG                g_BlockCount = 0;   /* 核心权限被裁掉的次数（会写事件） */
static LONG                g_QuietCount = 0;   /* 低危权限静默裁剪的次数（不写事件） */
static LONG                g_AllowUnload = 0;

static KSPIN_LOCK          g_EventLock;
static GUARD_EVENT         g_Events[GUARD_MAX_EVENTS];
static ULONG               g_EventHead = 0;
static ULONG               g_EventCount = 0;

/* altitude 必须全系统唯一。320000 是最常见的默认值，常被别的安全组件
   （HIPS / 杀软自保护）先占掉，此时 ObRegisterCallbacks 返回
   STATUS_FLT_INSTANCE_ALTITUDE_COLLISION (0xC01C0011)，加载直接失败。
   所以这里不写死，从基值往上逐个探测。 */
#define GUARD_ALTITUDE_BASE   349000
#define GUARD_ALTITUDE_TRIES  32

#ifndef STATUS_FLT_INSTANCE_ALTITUDE_COLLISION
#define STATUS_FLT_INSTANCE_ALTITUDE_COLLISION ((NTSTATUS)0xC01C0011L)
#endif

static UNICODE_STRING      g_AltitudeBuf;
static WCHAR               g_AltitudeText[16];
static ULONG               g_AltitudeValue = 0;

/* 实际使用的设备名。上次加载失败可能残留 \Device\sysguard 对象，
   这里允许换名重试，避免必须重启才能再加载。 */
static WCHAR               g_DevNameBuf[64];
static WCHAR               g_SymNameBuf[64];
static UNICODE_STRING      g_DevName;
static UNICODE_STRING      g_SymName;

/* ---------------- 事件日志 ---------------- */

static VOID GuardLogEvent(ULONG Type, HANDLE TargetPid, ULONG Access)
{
    KIRQL irql;
    LARGE_INTEGER now;
    ULONG idx;

    KeQuerySystemTime(&now);
    KeAcquireSpinLock(&g_EventLock, &irql);
    idx = g_EventHead;
    g_Events[idx].Time = now;
    g_Events[idx].Type = Type;
    g_Events[idx].TargetPid = HandleToULong(TargetPid);
    g_Events[idx].CallerPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    g_Events[idx].AccessMask = Access;
    g_EventHead = (idx + 1) % GUARD_MAX_EVENTS;
    if (g_EventCount < GUARD_MAX_EVENTS) {
        g_EventCount++;
    }
    KeReleaseSpinLock(&g_EventLock, irql);

    InterlockedIncrement(&g_BlockCount);
}

/* ---------------- 保护名单 ---------------- */

static BOOLEAN GuardIsProtected(HANDLE Pid)
{
    PLIST_ENTRY entry;
    KIRQL irql;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&g_ListLock, &irql);
    for (entry = g_ProtectList.Flink; entry != &g_ProtectList; entry = entry->Flink) {
        PGUARD_PROTECT_ENTRY item = CONTAINING_RECORD(entry, GUARD_PROTECT_ENTRY, ListEntry);
        if (item->Pid == Pid) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_ListLock, irql);
    return found;
}

static NTSTATUS GuardAddProtect(ULONG Pid)
{
    PGUARD_PROTECT_ENTRY item;
    KIRQL irql;

    if (Pid == 0 || Pid == 4) {
        return STATUS_INVALID_PARAMETER;   /* 拒绝保护 System / Idle */
    }

    KeAcquireSpinLock(&g_ListLock, &irql);
    {
        PLIST_ENTRY entry;
        for (entry = g_ProtectList.Flink; entry != &g_ProtectList; entry = entry->Flink) {
            PGUARD_PROTECT_ENTRY it = CONTAINING_RECORD(entry, GUARD_PROTECT_ENTRY, ListEntry);
            if (it->Pid == ULongToHandle(Pid)) {
                KeReleaseSpinLock(&g_ListLock, irql);
                return STATUS_ALREADY_REGISTERED;
            }
        }
    }
    if (g_ProtectedCount >= GUARD_MAX_PROTECT) {
        KeReleaseSpinLock(&g_ListLock, irql);
        return STATUS_QUOTA_EXCEEDED;
    }
    KeReleaseSpinLock(&g_ListLock, irql);

    item = (PGUARD_PROTECT_ENTRY)ExAllocatePoolWithTag(NonPagedPoolNx,
                                                       sizeof(GUARD_PROTECT_ENTRY),
                                                       GUARD_TAG);
    if (item == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    item->Pid = ULongToHandle(Pid);

    KeAcquireSpinLock(&g_ListLock, &irql);
    InsertTailList(&g_ProtectList, &item->ListEntry);
    g_ProtectedCount++;
    KeReleaseSpinLock(&g_ListLock, irql);

    return STATUS_SUCCESS;
}

static NTSTATUS GuardRemoveProtect(ULONG Pid)
{
    PLIST_ENTRY entry;
    KIRQL irql;
    NTSTATUS status = STATUS_NOT_FOUND;

    KeAcquireSpinLock(&g_ListLock, &irql);
    for (entry = g_ProtectList.Flink; entry != &g_ProtectList; entry = entry->Flink) {
        PGUARD_PROTECT_ENTRY item = CONTAINING_RECORD(entry, GUARD_PROTECT_ENTRY, ListEntry);
        if (item->Pid == ULongToHandle(Pid)) {
            RemoveEntryList(&item->ListEntry);
            g_ProtectedCount--;
            KeReleaseSpinLock(&g_ListLock, irql);
            ExFreePoolWithTag(item, GUARD_TAG);
            return STATUS_SUCCESS;
        }
    }
    KeReleaseSpinLock(&g_ListLock, irql);
    return status;
}

/* ---------------- 驱动级强制结束进程 ----------------

   调用者已经在 GuardCreateClose 里被验过 SeDebugPrivilege，所以这里不再做
   权限判断；真正要小心的是两件事：
     1) 目标是自己 —— IRP 会跟着进程一起消失，用户态永远等不到返回；
     2) 目标是保护名单里的进程 —— 默认拒绝，加 GUARD_KILL_FORCE 才先摘再杀，
        否则句柄回调会把自己刚开出来的 TERMINATE 权限裁掉（自锁死循环）。   */

static NTSTATUS
GuardKillProcess(ULONG Pid, ULONG Flags, PGUARD_KILL_RESULT Result)
{
    NTSTATUS status;
    HANDLE processHandle = NULL;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID cid;
    LARGE_INTEGER timeout;

    Result->Pid = Pid;
    Result->Method = 0;
    Result->Status = STATUS_SUCCESS;
    Result->Waited = 0;

    if (Pid == 0 || Pid == 4) {
        Result->Status = STATUS_INVALID_PARAMETER;   /* Idle / System 不碰 */
        return STATUS_INVALID_PARAMETER;
    }

    if (Pid == HandleToULong(PsGetCurrentProcessId())) {
        /* 结束自己 = 这个 IRP 永远没人收尾，用户态会一直卡在 DeviceIoControl */
        Result->Status = STATUS_INVALID_PARAMETER;
        return STATUS_INVALID_PARAMETER;
    }

    if (GuardIsProtected(ULongToHandle(Pid))) {
        if ((Flags & GUARD_KILL_FORCE) == 0) {
            InterlockedIncrement(&g_BlockCount);
            GuardLogEvent(1, ULongToHandle(Pid), PROCESS_TERMINATE);
            Result->Status = STATUS_ACCESS_DENIED;
            return STATUS_ACCESS_DENIED;
        }
        GuardRemoveProtect(Pid);
        Result->Method |= GUARD_KILL_M_UNPROTECT;
    }

    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    cid.UniqueProcess = ULongToHandle(Pid);
    cid.UniqueThread = NULL;

    /* SYNCHRONIZE 只为了后面能等它退出；真正要的是 PROCESS_TERMINATE */
    status = ZwOpenProcess(&processHandle, PROCESS_TERMINATE | SYNCHRONIZE, &oa, &cid);
    if (!NT_SUCCESS(status)) {
        Result->Status = status;     /* 0xC000000B 进程已退出 / PID 不存在 */
        return status;
    }

    Result->Method |= GUARD_KILL_M_KERNEL;
    status = ZwTerminateProcess(processHandle, STATUS_SUCCESS);

    if (NT_SUCCESS(status) && (Flags & GUARD_KILL_NO_WAIT) == 0) {
        /* 相对时间用负数，5 秒。等不到只是"没确认"，不改变已经下发的事实。

           这里踩过一个致命的坑：最初直接把 processHandle 传给
           KeWaitForSingleObject。那个函数的第一个参数是「指向调度器对象的
           指针」（PKMUTANT/PDISPATCHER_HEADER），根本不接受句柄。把句柄这种
           小整数传进去，内核会拿它当地址读 [obj]、并往 obj 的等待链表里插入，
           直接 0x0000000A（IRQL_NOT_LESS_OR_EQUAL，写，IRQL 2）。两次蓝屏
           都是这一行。

           正确做法：句柄 -> ObReferenceObjectByHandle 换出真正的对象指针，
           等完再 ObDereferenceObject 还引用。 */
        PVOID waitObject = NULL;

        timeout.QuadPart = -(LONGLONG)GUARD_KILL_WAIT_MS * 10000LL;
        if (NT_SUCCESS(ObReferenceObjectByHandle(processHandle, SYNCHRONIZE, NULL,
                                                 KernelMode, &waitObject, NULL)) &&
            waitObject != NULL) {
            if (KeWaitForSingleObject(waitObject, Executive, KernelMode,
                                      FALSE, &timeout) == STATUS_SUCCESS) {
                Result->Waited = 1;
            }
            ObDereferenceObject(waitObject);
        }
    }

    ZwClose(processHandle);

    if (NT_SUCCESS(status)) {
        GuardLogEvent(6, ULongToHandle(Pid), 0);
    }
    Result->Status = status;
    return status;
}

/* ---------------- Ob 回调：核心自保护 ---------------- */

static OB_PREOP_CALLBACK_STATUS
GuardPreProcess(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info)
{
    PACCESS_MASK desired;
    HANDLE pid;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (Info->KernelHandle || !g_Config.EnableProcess) {
        return OB_PREOP_SUCCESS;
    }

    if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
        desired = &Info->Parameters->CreateHandleInformation.DesiredAccess;
    } else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        desired = &Info->Parameters->DuplicateHandleInformation.DesiredAccess;
    } else {
        return OB_PREOP_SUCCESS;
    }

    pid = PsGetProcessId((PEPROCESS)Info->Object);

    if (pid == NULL || pid == ULongToHandle(4)) {
        return OB_PREOP_SUCCESS;
    }

    if (!GuardIsProtected(pid)) {
        return OB_PREOP_SUCCESS;
    }

    {
        ACCESS_MASK coreHit = *desired & GUARD_PROC_CORE;
        ACCESS_MASK quietHit = *desired & GUARD_PROC_QUIET;

        *desired &= ~(GUARD_PROC_CORE | GUARD_PROC_QUIET);

        if (coreHit != 0) {
            GuardLogEvent(1, pid, (ULONG)coreHit);
        } else if (quietHit != 0) {
            InterlockedIncrement(&g_QuietCount);   /* 静默裁剪：只计数，不记录 */
        }
    }

    return OB_PREOP_SUCCESS;
}

static OB_PREOP_CALLBACK_STATUS
GuardPreThread(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION Info)
{
    PACCESS_MASK desired;
    PETHREAD thread;
    HANDLE pid;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (Info->KernelHandle || !g_Config.EnableThread) {
        return OB_PREOP_SUCCESS;
    }

    if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
        desired = &Info->Parameters->CreateHandleInformation.DesiredAccess;
    } else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        desired = &Info->Parameters->DuplicateHandleInformation.DesiredAccess;
    } else {
        return OB_PREOP_SUCCESS;
    }

    thread = (PETHREAD)Info->Object;
    pid = PsGetThreadProcessId(thread);

    if (pid == NULL || pid == ULongToHandle(4)) {
        return OB_PREOP_SUCCESS;
    }
    if (!GuardIsProtected(pid)) {
        return OB_PREOP_SUCCESS;
    }

    {
        ACCESS_MASK coreHit = *desired & GUARD_THREAD_CORE;
        ACCESS_MASK quietHit = *desired & GUARD_THREAD_QUIET;

        *desired &= ~(GUARD_THREAD_CORE | GUARD_THREAD_QUIET);

        if (coreHit != 0) {
            GuardLogEvent(2, pid, (ULONG)coreHit);
        } else if (quietHit != 0) {
            InterlockedIncrement(&g_QuietCount);
        }
    }

    return OB_PREOP_SUCCESS;
}

/* ---------------- 注册表回调：锁死服务键 ----------------

   这里踩过一个坑：最初用「回调里的 Object == 自己 ObReferenceObjectByHandle
   拿到的指针」来判断是不是自己的服务键。这个判据不可靠 —— 同一个注册表键
   可以有多个 key object，SCM 删服务时走的那个对象和我们持有的不是同一个，
   于是比对永远不成立，防护形同虚设（sc delete 一删就掉）。

   可靠做法是用 CmCallbackGetKeyObjectIDEx 取该对象的**完整路径名**，
   再做大小写无关的比对。路径名取到的是 \Registry\Machine\System\
   CurrentControlSet\Services\<name> 这种内核格式，所以比对「\SERVICES\<服务名>」
   这个后缀，顺带兼容 ControlSet001 这类写法。

   注意：文档明确警告通知结构里的 Object 有时是非法的非 NULL 指针，
   必须先判空、并且只把它交给 CmCallbackGetKeyObjectIDEx，不要解引用。 */

static BOOLEAN GuardKeyIsOurs(PVOID Object)
{
    PCUNICODE_STRING name = NULL;
    ULONG_PTR id = 0;
    USHORT i, n, slen;
    BOOLEAN match = FALSE;
    NTSTATUS status;

    if (Object == NULL) {
        return FALSE;
    }
    if (Object == g_ServiceKeyObject) {     /* 快路径：指针一致就不用查名字 */
        return TRUE;
    }
    if (!g_RegRegistered) {
        return FALSE;
    }

    status = CmCallbackGetKeyObjectIDEx(&g_RegCookieValue, Object, &id, &name, 0);
    if (!NT_SUCCESS(status) || name == NULL ||
        name->Buffer == NULL || name->Length == 0) {
        return FALSE;
    }

    for (slen = 0; g_ServiceSuffix[slen] != L'\0'; slen++) {
        /* 仅计算长度 */
    }

    n = name->Length / sizeof(WCHAR);
    if (n >= slen) {
        match = TRUE;
        for (i = 0; i < slen; i++) {
            WCHAR c = name->Buffer[n - slen + i];
            if (c >= L'a' && c <= L'z') {
                c = (WCHAR)(c - (L'a' - L'A'));
            }
            if (c != g_ServiceSuffix[i]) {
                match = FALSE;
                break;
            }
        }
    }

    CmCallbackReleaseKeyObjectIDEx(name);
    return match;
}

static NTSTATUS
GuardRegCallback(PVOID Cookie, PVOID Argument1, PVOID Argument2)
{
    REG_NOTIFY_CLASS cls = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    PVOID target = NULL;

    UNREFERENCED_PARAMETER(Cookie);

    if (!g_Config.EnableRegistry) {
        return STATUS_SUCCESS;
    }

    switch (cls) {
    case RegNtPreDeleteKey:
        target = ((PREG_DELETE_KEY_INFORMATION)Argument2)->Object;
        break;
    case RegNtPreSetValueKey:
        target = ((PREG_SET_VALUE_KEY_INFORMATION)Argument2)->Object;
        break;
    case RegNtPreDeleteValueKey:
        target = ((PREG_DELETE_VALUE_KEY_INFORMATION)Argument2)->Object;
        break;
    case RegNtPreSetInformationKey:          /* 改键名 / 改安全描述符 */
        target = ((PREG_SET_INFORMATION_KEY_INFORMATION)Argument2)->Object;
        break;
    default:
        return STATUS_SUCCESS;
    }

    if (GuardKeyIsOurs(target)) {
        GuardLogEvent(3, ULongToHandle(0), (ULONG)cls);
        return STATUS_ACCESS_DENIED;
    }

    return STATUS_SUCCESS;
}

/* ---------------- 卸载控制 ----------------

   这里有一个很容易踩的坑：DriverUnload 返回 VOID，没有任何「拒绝卸载」的通道。
   只要这个例程被调用并返回，内核就一定会把镜像卸掉 —— 在函数里 return 或
   记录一条日志都拦不住（旧版本就是这样，属于假防护，sc stop 一试就穿）。

   真正的「拒绝停止」只有一种实现：DriverEntry 里根本不设置
   DriverObject->DriverUnload。此时内核的 IopUnloadDriver 返回
   STATUS_INVALID_DEVICE_REQUEST，SCM 报 1052（服务无法接受控制）。

   为了仍然能卸载（开发/卸载流程），提供两个后门：
     - IOCTL_GUARD_UNLOAD + 令牌：动态把该例程装回去，之后 sc stop 正常生效；
     - 配置里关掉「驱动自锁」：同样装回该例程。
                                             */
static VOID GuardDriverUnload(PDRIVER_OBJECT DriverObject)
{
    PLIST_ENTRY entry;

    UNREFERENCED_PARAMETER(DriverObject);

    GuardLogEvent(4, ULongToHandle(0), 0);

    if (g_ObProcessCookie != NULL) {
        ObUnRegisterCallbacks(g_ObProcessCookie);
        g_ObProcessCookie = NULL;
    }
    if (g_ObThreadCookie != NULL) {
        ObUnRegisterCallbacks(g_ObThreadCookie);
        g_ObThreadCookie = NULL;
    }
    if (g_RegRegistered) {
        CmUnRegisterCallback(g_RegCookieValue);
        g_RegRegistered = FALSE;
    }
    if (g_ServiceKeyObject != NULL) {
        ObDereferenceObject(g_ServiceKeyObject);
        g_ServiceKeyObject = NULL;
    }

    /* 释放保护名单。
       这里必须先把 next 取出来再释放当前项 —— GUARD_PROTECT_ENTRY 的
       ListEntry 是第一个成员，item 和 entry 是同一个地址。若写成
       for (; entry != head; entry = entry->Flink) 并在循环体里释放 item，
       第二轮就会从已释放的内存里读 Flink：那块内存早已被内存管理器改写成
       空闲链表链接，于是拿到一个野指针并把它交给 ExFreePoolWithTag，
       在持有 pool 锁（IRQL 2）时对野指针置位 -> 0x0000000A 蓝屏。
       v5 在“保护名单非空 + 卸载驱动”时必崩，就是这么来的。 */
    entry = g_ProtectList.Flink;
    while (entry != &g_ProtectList) {
        PGUARD_PROTECT_ENTRY item = CONTAINING_RECORD(entry, GUARD_PROTECT_ENTRY, ListEntry);

        entry = entry->Flink;            /* 先取后继，再释放当前 */
        ExFreePoolWithTag(item, GUARD_TAG);
    }
    InitializeListHead(&g_ProtectList);
    g_ProtectedCount = 0;

    if (g_SymName.Length != 0) {
        IoDeleteSymbolicLink(&g_SymName);
    }

    if (g_DeviceObject != NULL) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }
}

/*
 * 装上/撤掉卸载例程。
 * allowed = FALSE 时 DriverObject->DriverUnload 变成 NULL，SCM 的 stop 立刻失效。
 * 运行期修改这个指针是安全的：驱动对象不在 PatchGuard 的保护区里。
 */
static VOID GuardSetUnloadAllowed(BOOLEAN allowed)
{
    if (g_DriverObject == NULL) {
        return;
    }
    g_DriverObject->DriverUnload = allowed ? GuardDriverUnload : NULL;
}

/* ---------------- 派遣例程 ---------------- */

static NTSTATUS
GuardCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);

    UNREFERENCED_PARAMETER(DeviceObject);

    /* 只有持有 SeDebugPrivilege 的调用者（管理员）才能打开控制设备，
       防止普通用户直接把进程移出保护名单或下发卸载令牌 */
    if (sp->MajorFunction == IRP_MJ_CREATE) {
        LUID debugLuid;
        debugLuid.LowPart = 20;      /* SE_DEBUG_PRIVILEGE */
        debugLuid.HighPart = 0;
        if (!SeSinglePrivilegeCheck(debugLuid, UserMode)) {
            Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_ACCESS_DENIED;
        }
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS
GuardDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inLen = sp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = sp->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG code = sp->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG info = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (code) {

    case IOCTL_GUARD_PROTECT:
        if (buffer != NULL && inLen >= sizeof(ULONG) && outLen >= sizeof(ULONG)) {
            status = GuardAddProtect(*(PULONG)buffer);
            *(PULONG)buffer = g_ProtectedCount;
            info = sizeof(ULONG);
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;

    case IOCTL_GUARD_UNPROTECT:
        if (buffer != NULL && inLen >= sizeof(ULONG) && outLen >= sizeof(ULONG)) {
            status = GuardRemoveProtect(*(PULONG)buffer);
            *(PULONG)buffer = g_ProtectedCount;
            info = sizeof(ULONG);
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;

    case IOCTL_GUARD_QUERY:
        if (buffer != NULL && outLen >= sizeof(GUARD_STATE)) {
            GUARD_STATE *st = (GUARD_STATE *)buffer;
            RtlZeroMemory(st, sizeof(GUARD_STATE));
            st->Version = GUARD_VERSION;
            st->ProtectedCount = g_ProtectedCount;
            st->BlockCount = (ULONG)g_BlockCount;
            st->QuietCount = (ULONG)g_QuietCount;
            st->Loaded = 1;
            st->Config = g_Config;
            info = sizeof(GUARD_STATE);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_GUARD_SET_CONFIG:
        if (buffer != NULL && inLen >= sizeof(GUARD_CONFIG)) {
            GUARD_CONFIG *cfg = (GUARD_CONFIG *)buffer;
            g_Config.EnableProcess = cfg->EnableProcess ? 1 : 0;
            g_Config.EnableThread = cfg->EnableThread ? 1 : 0;
            g_Config.EnableRegistry = cfg->EnableRegistry ? 1 : 0;
            g_Config.EnableUnload = cfg->EnableUnload ? 1 : 0;
            /* 自锁开关要立刻反映到卸载例程上，否则改了也没用 */
            GuardSetUnloadAllowed(g_Config.EnableUnload ? FALSE : TRUE);
            GuardLogEvent(5, ULongToHandle(0), 0);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;

    case IOCTL_GUARD_GET_EVENTS:
        if (buffer != NULL && outLen >= sizeof(GUARD_EVENT)) {
            KIRQL irql;
            ULONG maxItems = outLen / sizeof(GUARD_EVENT);
            ULONG n, i, start;

            KeAcquireSpinLock(&g_EventLock, &irql);
            n = g_EventCount;
            if (n > maxItems) {
                n = maxItems;
            }
            start = (g_EventHead + GUARD_MAX_EVENTS - g_EventCount) % GUARD_MAX_EVENTS;
            for (i = 0; i < n; i++) {
                ((GUARD_EVENT *)buffer)[i] = g_Events[(start + i) % GUARD_MAX_EVENTS];
            }
            KeReleaseSpinLock(&g_EventLock, irql);

            info = n * sizeof(GUARD_EVENT);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_GUARD_CLEAR_EVENT:
    {
        KIRQL irql;
        KeAcquireSpinLock(&g_EventLock, &irql);
        g_EventCount = 0;
        g_EventHead = 0;
        KeReleaseSpinLock(&g_EventLock, irql);
        InterlockedExchange(&g_BlockCount, 0);
        InterlockedExchange(&g_QuietCount, 0);
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_GUARD_LIST_PIDS:
        if (buffer != NULL && outLen >= sizeof(ULONG)) {
            KIRQL irql;
            ULONG maxItems = outLen / sizeof(ULONG);
            ULONG n = 0;
            PLIST_ENTRY entry;

            KeAcquireSpinLock(&g_ListLock, &irql);
            for (entry = g_ProtectList.Flink; entry != &g_ProtectList && n < maxItems; entry = entry->Flink) {
                PGUARD_PROTECT_ENTRY item = CONTAINING_RECORD(entry, GUARD_PROTECT_ENTRY, ListEntry);
                ((PULONG)buffer)[n++] = HandleToULong(item->Pid);
            }
            KeReleaseSpinLock(&g_ListLock, irql);
            info = n * sizeof(ULONG);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_GUARD_KILL:
        if (buffer != NULL && inLen >= sizeof(GUARD_KILL_REQUEST) &&
            outLen >= sizeof(GUARD_KILL_RESULT)) {
            /* 输入输出共用同一块 SystemBuffer，先把请求读成局部变量，
               再清零改写成结果，避免自己把自己的参数抹掉 */
            ULONG pid = ((PGUARD_KILL_REQUEST)buffer)->Pid;
            ULONG flags = ((PGUARD_KILL_REQUEST)buffer)->Flags;

            RtlZeroMemory(buffer, sizeof(GUARD_KILL_RESULT));
            GuardKillProcess(pid, flags, (PGUARD_KILL_RESULT)buffer);
            info = sizeof(GUARD_KILL_RESULT);

            /* IRP 本身恒为成功：真正的 NTSTATUS 放在结果结构里。
               否则用户态只能看到 ERROR_ACCESS_DENIED 这一个笼统值，
               分不清是"被自我保护拒绝"还是"进程已不存在"。 */
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_INVALID_PARAMETER;
        }
        break;

    case IOCTL_GUARD_UNLOAD:
        if (buffer != NULL && inLen >= sizeof(ULONG) && *(PULONG)buffer == GUARD_UNLOAD_TOKEN) {
            InterlockedExchange(&g_AllowUnload, 1);
            /* 令牌到位后把卸载例程装回去，之后的 sc stop 才能真的停掉 */
            GuardSetUnloadAllowed(TRUE);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_ACCESS_DENIED;
        }
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* ---------------- 让 ObRegisterCallbacks 通过签名校验 ----------------

   ObRegisterCallbacks 内部会调用 MmVerifyCallbackFunction，检查调用者驱动
   镜像的 LDR_DATA_TABLE_ENTRY->Flags。Windows 在 test signing 模式下加载
   驱动后，会把这个标记置为"未通过有效签名校验"，于是注册直接返回
   STATUS_ACCESS_DENIED (0xC0000022) —— 这与 sc start 能否加载是两回事。

   开发机上把自己这一项的 Flags 补上 LDRP_IMAGE_INTEGRITY_FORCED(0x20)，
   是业界通用的本地调试手段。正式发布必须使用真实 EV/WHQL 签名，
   不要带着这个补丁上生产。                                        */

typedef struct _GUARD_LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;                 /* x64 上位于 0x68 */
} GUARD_LDR_ENTRY, *PGUARD_LDR_ENTRY;

/* 编译期校验结构布局，偏移算错会直接编译失败，而不是运行期蓝屏 */
C_ASSERT(FIELD_OFFSET(GUARD_LDR_ENTRY, Flags) == 0x68);

static VOID GuardMarkImageSigned(PDRIVER_OBJECT DriverObject)
{
#ifdef SG_NO_LDR_PATCH
    /* 诊断版本：不打补丁，用来确认「加载失败」是否由这段内容引起 */
    UNREFERENCED_PARAMETER(DriverObject);
#else
    PGUARD_LDR_ENTRY ldr = (PGUARD_LDR_ENTRY)DriverObject->DriverSection;
    if (ldr != NULL) {
        ldr->Flags |= 0x20;
    }
#endif
}

/* ---------------- 加载诊断面包屑 ---------------- */

typedef struct _GUARD_BREADCRUMB {
    ULONG Step;
    ULONG Status;
} GUARD_BREADCRUMB;

/* 从 RegistryPath 推自身的服务键路径与 Parameters 子键。
   服务名可能是 sysguard / sysguard2 / 任意名字，写死会在换名后失去自保护。 */
static VOID GuardInitPaths(PUNICODE_STRING RegistryPath)
{
    WCHAR name[64];
    USHORT i, len, nameStart;
    WCHAR c;

    if (RegistryPath != NULL && RegistryPath->Buffer != NULL && RegistryPath->Length > 0) {
        RtlStringCchCopyNW(g_ServiceKeyBuf, RTL_NUMBER_OF(g_ServiceKeyBuf),
                           RegistryPath->Buffer,
                           RegistryPath->Length / sizeof(WCHAR));
    } else {
        RtlStringCchCopyW(g_ServiceKeyBuf, RTL_NUMBER_OF(g_ServiceKeyBuf),
                          GUARD_SERVICE_KEY);
    }
    RtlInitUnicodeString(&g_ServiceKeyPath, g_ServiceKeyBuf);

    RtlStringCchCopyW(g_ParamKeyBuf, RTL_NUMBER_OF(g_ParamKeyBuf), g_ServiceKeyBuf);
    RtlStringCchCatW(g_ParamKeyBuf, RTL_NUMBER_OF(g_ParamKeyBuf), L"\\Parameters");
    RtlInitUnicodeString(&g_ParamKeyPath, g_ParamKeyBuf);

    /* 取最后一段作为服务名，构造大写后缀 "\SERVICES\<NAME>" */
    len = g_ServiceKeyPath.Length / sizeof(WCHAR);
    nameStart = len;
    while (nameStart > 0 && g_ServiceKeyBuf[nameStart - 1] != L'\\') {
        nameStart--;
    }
    RtlStringCchCopyNW(name, RTL_NUMBER_OF(name),
                       g_ServiceKeyBuf + nameStart, len - nameStart);
    for (i = 0; name[i] != L'\0'; i++) {
        c = name[i];
        if (c >= L'a' && c <= L'z') {
            name[i] = (WCHAR)(c - (L'a' - L'A'));
        }
    }
    RtlStringCchCopyW(g_ServiceSuffix, RTL_NUMBER_OF(g_ServiceSuffix), L"\\SERVICES\\");
    RtlStringCchCatW(g_ServiceSuffix, RTL_NUMBER_OF(g_ServiceSuffix), name);
}

/* 把 DriverEntry 走到哪一步、返回值是什么写进注册表。
   驱动加载失败时用户态看不到任何输出，靠这个定位。 */
static VOID GuardBreadcrumb(ULONG Step, NTSTATUS Status)
{
    UNICODE_STRING keyPath, valueName;
    OBJECT_ATTRIBUTES oa;
    HANDLE hKey;
    GUARD_BREADCRUMB bc;

    keyPath = g_ParamKeyPath;
    if (keyPath.Buffer == NULL) {
        return;
    }
    InitializeObjectAttributes(&oa, &keyPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    if (!NT_SUCCESS(ZwCreateKey(&hKey, KEY_SET_VALUE, &oa, 0, NULL,
                                REG_OPTION_NON_VOLATILE, NULL))) {
        return;
    }

    bc.Step = Step;
    bc.Status = (ULONG)Status;
    RtlInitUnicodeString(&valueName, L"Breadcrumb");
    ZwSetValueKey(hKey, &valueName, 0, REG_BINARY, &bc, sizeof(bc));
    ZwClose(hKey);
}

/* 把实际使用的设备名写进注册表，用户态据此精确打开，
   避免碰到上次加载失败残留的同名空壳设备 */
static VOID GuardPublishDeviceName(PUNICODE_STRING Name)
{
    UNICODE_STRING keyPath, valueName;
    OBJECT_ATTRIBUTES oa;
    HANDLE hKey;

    keyPath = g_ParamKeyPath;
    if (keyPath.Buffer == NULL) {
        return;
    }
    InitializeObjectAttributes(&oa, &keyPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    if (!NT_SUCCESS(ZwCreateKey(&hKey, KEY_SET_VALUE, &oa, 0, NULL,
                                REG_OPTION_NON_VOLATILE, NULL))) {
        return;
    }

    RtlInitUnicodeString(&valueName, L"DeviceName");
    ZwSetValueKey(hKey, &valueName, 0, REG_SZ, Name->Buffer, Name->Length + sizeof(WCHAR));
    ZwClose(hKey);
}

/* 把「当前活跃实例」写到固定位置 HKLM\SOFTWARE\SysGuard。
   换服务名做版本对比时机器上可能同时有两个实例，用户态若靠 \\.\sysguard1..9
   逐个探测，会开到旧的那个。这里每次加载覆盖，用户态只信这个值。 */
static VOID GuardPublishActiveDevice(PUNICODE_STRING SymName, PUNICODE_STRING ServicePath)
{
    UNICODE_STRING keyPath, valueName;
    OBJECT_ATTRIBUTES oa;
    HANDLE hKey;

    RtlInitUnicodeString(&keyPath, L"\\Registry\\Machine\\SOFTWARE\\SysGuard");
    InitializeObjectAttributes(&oa, &keyPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    if (!NT_SUCCESS(ZwCreateKey(&hKey, KEY_SET_VALUE, &oa, 0, NULL,
                                REG_OPTION_NON_VOLATILE, NULL))) {
        return;
    }

    RtlInitUnicodeString(&valueName, L"ActiveDevice");
    ZwSetValueKey(hKey, &valueName, 0, REG_SZ,
                  SymName->Buffer, SymName->Length + sizeof(WCHAR));

    RtlInitUnicodeString(&valueName, L"Service");
    ZwSetValueKey(hKey, &valueName, 0, REG_SZ,
                  ServicePath->Buffer, ServicePath->Length + sizeof(WCHAR));

    ZwClose(hKey);
}

/* 把某个数值格式化成 6 位 altitude 字符串，并同步到 g_AltitudeBuf */
static VOID GuardSetAltitude(ULONG Value)
{
    RtlStringCchPrintfW(g_AltitudeText, RTL_NUMBER_OF(g_AltitudeText),
                        L"%06lu", Value);
    RtlInitUnicodeString(&g_AltitudeBuf, g_AltitudeText);
}

/* 把实际占用的 altitude 写进注册表，排查撞车时一眼能看出来 */
static VOID GuardPublishAltitude(PUNICODE_STRING Alt)
{
    UNICODE_STRING keyPath, valueName;
    OBJECT_ATTRIBUTES oa;
    HANDLE hKey;

    keyPath = g_ParamKeyPath;
    if (keyPath.Buffer == NULL) {
        return;
    }
    InitializeObjectAttributes(&oa, &keyPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    if (!NT_SUCCESS(ZwCreateKey(&hKey, KEY_SET_VALUE, &oa, 0, NULL,
                                REG_OPTION_NON_VOLATILE, NULL))) {
        return;
    }

    RtlInitUnicodeString(&valueName, L"Altitude");
    ZwSetValueKey(hKey, &valueName, 0, REG_SZ, Alt->Buffer, Alt->Length + sizeof(WCHAR));
    ZwClose(hKey);
}

/* ---------------- DriverEntry ---------------- */

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING keyPath;
    OBJECT_ATTRIBUTES oa;
    HANDLE hKey = NULL;
    ULONG index;
    OB_CALLBACK_REGISTRATION obReg;
    OB_OPERATION_REGISTRATION opReg[2];

    UNREFERENCED_PARAMETER(RegistryPath);

    GuardInitPaths(RegistryPath);

    GuardBreadcrumb(0, STATUS_SUCCESS);   /* DriverEntry 已经跑起来了 */

    g_DriverObject = DriverObject;
    InitializeListHead(&g_ProtectList);
    KeInitializeSpinLock(&g_ListLock);
    KeInitializeSpinLock(&g_EventLock);

    g_Config.EnableProcess = 1;
    g_Config.EnableThread = 1;
    g_Config.EnableRegistry = 1;
    g_Config.EnableUnload = 1;

    g_AllowUnload = 0;

    /* 1. 创建设备（名字撞车时换后缀重试，最多 10 次） */
    status = STATUS_OBJECT_NAME_COLLISION;
    for (index = 0; index < 10; index++) {
        if (index == 0) {
            RtlStringCchCopyW(g_DevNameBuf, RTL_NUMBER_OF(g_DevNameBuf), GUARD_DEVICE_NAME);
            RtlStringCchCopyW(g_SymNameBuf, RTL_NUMBER_OF(g_SymNameBuf), GUARD_SYMLINK_NAME);
        } else {
            RtlStringCchPrintfW(g_DevNameBuf, RTL_NUMBER_OF(g_DevNameBuf),
                                L"\\Device\\sysguard%d", index);
            RtlStringCchPrintfW(g_SymNameBuf, RTL_NUMBER_OF(g_SymNameBuf),
                                L"\\DosDevices\\sysguard%d", index);
        }
        RtlInitUnicodeString(&g_DevName, g_DevNameBuf);
        RtlInitUnicodeString(&g_SymName, g_SymNameBuf);

        status = IoCreateDevice(DriverObject, 0, &g_DevName,
                                FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
                                FALSE, &g_DeviceObject);
        if (NT_SUCCESS(status)) {
            break;
        }
        if (status != STATUS_OBJECT_NAME_COLLISION) {
            break;
        }
        g_DeviceObject = NULL;
    }

    if (!NT_SUCCESS(status)) {
        GuardBreadcrumb(1, status);       /* 1 = IoCreateDevice 失败 */
        return status;
    }
    GuardBreadcrumb(1, STATUS_SUCCESS);

    status = IoCreateSymbolicLink(&g_SymName, &g_DevName);
    if (!NT_SUCCESS(status)) {
        GuardBreadcrumb(2, status);       /* 2 = 符号链接失败 */
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }
    GuardBreadcrumb(2, STATUS_SUCCESS);
    GuardPublishDeviceName(&g_SymName);
    GuardPublishActiveDevice(&g_SymName, &g_ServiceKeyPath);

    DriverObject->MajorFunction[IRP_MJ_CREATE] = GuardCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = GuardCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = GuardDeviceControl;

    /*
     * 关键：默认不设置 DriverUnload。
     * 没有卸载例程的驱动内核不允许卸载，sc stop 会直接失败（1052），
     * 这才是「拒绝停止」唯一可靠的做法。需要卸载时由令牌 IOCTL
     * 或关掉「驱动自锁」把例程装回去。
     */
    DriverObject->DriverUnload = NULL;

    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    /* 2. 注册 Ob 回调 —— 自保护核心 */
    GuardMarkImageSigned(DriverObject);   /* 必须在 ObRegisterCallbacks 之前 */

    RtlZeroMemory(opReg, sizeof(opReg));
    opReg[0].ObjectType = PsProcessType;
    opReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg[0].PreOperation = GuardPreProcess;
    opReg[0].PostOperation = NULL;

    opReg[1].ObjectType = PsThreadType;
    opReg[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg[1].PreOperation = GuardPreThread;
    opReg[1].PostOperation = NULL;

    RtlZeroMemory(&obReg, sizeof(obReg));
    obReg.Version = OB_FLT_REGISTRATION_VERSION;
    obReg.OperationRegistrationCount = 2;
    obReg.RegistrationContext = NULL;
    obReg.OperationRegistration = opReg;

    /* altitude 撞车 -> 换下一个值重试；其它错误立即放弃 */
    status = STATUS_FLT_INSTANCE_ALTITUDE_COLLISION;
    for (index = 0; index < GUARD_ALTITUDE_TRIES; index++) {
        ULONG value = GUARD_ALTITUDE_BASE + index;

        GuardSetAltitude(value);
        obReg.Altitude = g_AltitudeBuf;

        status = ObRegisterCallbacks(&obReg, &g_ObProcessCookie);
        if (status != STATUS_FLT_INSTANCE_ALTITUDE_COLLISION) {
            if (NT_SUCCESS(status)) {
                g_AltitudeValue = value;
                GuardPublishAltitude(&g_AltitudeBuf);
            }
            break;
        }
    }

    if (NT_SUCCESS(status)) {
        /* 单次注册即覆盖进程与线程两个类型，cookie 已足够 */
        g_ObThreadCookie = NULL;
        GuardBreadcrumb(3, STATUS_SUCCESS);
    } else {
        g_ObProcessCookie = NULL;
        GuardBreadcrumb(3, status);       /* 3 = ObRegisterCallbacks 失败 */

        /*
         * 关键：失败必须把符号链接和设备一起删掉。
         * 内核把镜像卸载后，残留的 \Device\sysguard 仍然能被 CreateFile 打开，
         * 而它背后的驱动代码已经不在了 —— 用户态再发 IOCTL 就是访问已释放内存。
         * 上一次失败正是漏了这一步，才留下那个「空壳设备」。
         */
        IoDeleteSymbolicLink(&g_SymName);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        DriverObject->DriverUnload = NULL;
        return status;
    }

    /* 3. 注册表回调 —— 锁死服务键 */
    keyPath = g_ServiceKeyPath;
    InitializeObjectAttributes(&oa, &keyPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    status = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &oa);
    GuardBreadcrumb(4, status);           /* 4 = 打开自身服务键 */
    if (NT_SUCCESS(status)) {
        NTSTATUS refStatus;

        refStatus = ObReferenceObjectByHandle(hKey, 0, NULL, KernelMode,
                                              &g_ServiceKeyObject, NULL);
        GuardBreadcrumb(5, refStatus);    /* 5 = 取服务键对象 */
        ZwClose(hKey);
        if (!NT_SUCCESS(refStatus)) {
            g_ServiceKeyObject = NULL;
        }
    }

    if (g_ServiceKeyObject != NULL) {
        /* 注册表回调的 altitude 也是独立命名空间，同样可能撞车 */
        status = STATUS_FLT_INSTANCE_ALTITUDE_COLLISION;
        for (index = 0; index < GUARD_ALTITUDE_TRIES; index++) {
            GuardSetAltitude(GUARD_ALTITUDE_BASE + 500 + index);
            status = CmRegisterCallbackEx(GuardRegCallback, &g_AltitudeBuf,
                                          DriverObject, NULL,
                                          &g_RegCookieValue, NULL);
            if (status != STATUS_FLT_INSTANCE_ALTITUDE_COLLISION) {
                break;
            }
        }
        if (NT_SUCCESS(status)) {
            g_RegRegistered = TRUE;
            GuardBreadcrumb(6, STATUS_SUCCESS);   /* 6 = 注册表回调已就绪 */
        } else {
            g_RegRegistered = FALSE;
            GuardBreadcrumb(6, status);           /* 6 = CmRegisterCallbackEx 失败 */
        }
    } else {
        GuardBreadcrumb(6, STATUS_INVALID_HANDLE);
    }

    GuardBreadcrumb(9, STATUS_SUCCESS);   /* 9 = 加载完成 */
    return STATUS_SUCCESS;
}
