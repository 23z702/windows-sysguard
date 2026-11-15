/*
 * probe.c —— 最小对照驱动
 *
 * 唯一作用：证明「这台机器现在能不能加载一个自定义内核驱动」。
 * 不创建设备、不注册回调、不做任何保护，DriverEntry 只往注册表写一个标记。
 *
 * 判定方式：
 *   加载成功 -> HKLM\SOFTWARE\SysGuardProbe 下出现 Entered 值
 *   加载失败 -> 没有该键，且 sc start 返回具体错误码
 *
 * 用途：把「环境问题」和「sysguard 自身内容问题」彻底分开。
 */

#include <ntddk.h>

#define PROBE_TAG 0x504F5250u   /* 'PROM' */

static VOID ProbeWriteMarker(ULONG Stage)
{
    UNICODE_STRING keyPath, valueName;
    OBJECT_ATTRIBUTES oa;
    HANDLE hKey = NULL;
    NTSTATUS status;
    ULONG payload[2];

    payload[0] = PROBE_TAG;
    payload[1] = Stage;

    RtlInitUnicodeString(&keyPath, L"\\Registry\\Machine\\SOFTWARE\\SysGuardProbe");
    InitializeObjectAttributes(&oa, &keyPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    status = ZwCreateKey(&hKey, KEY_SET_VALUE, &oa, 0, NULL,
                         REG_OPTION_NON_VOLATILE, NULL);
    if (NT_SUCCESS(status)) {
        RtlInitUnicodeString(&valueName, L"Entered");
        ZwSetValueKey(hKey, &valueName, 0, REG_BINARY, payload, sizeof(payload));
        ZwClose(hKey);
    }
}

static VOID ProbeUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    ProbeWriteMarker(2);
}

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    /* 先把标记写下来：能走到这一行，说明镜像已经被内核成功映射并调用了入口 */
    ProbeWriteMarker(1);

    DriverObject->DriverUnload = ProbeUnload;
    return STATUS_SUCCESS;
}
