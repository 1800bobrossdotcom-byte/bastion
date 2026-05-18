// BastionFilter.c
// ----------------------------------------------------------------------------
// Bastion on-access kernel minifilter (Path B).
//
// Pattern follows Microsoft's "scanner" minifilter sample (Windows-driver-
// samples / filesys / miniFilter / scanner). Differences:
//   * We only care about IRP_MJ_CREATE post-op (write-open + execute-open).
//   * Verdict logic lives ENTIRELY in user-mode (`bastion-agent`), reusing
//     the same `scan_engine` that powers the notify watcher and AMSI provider.
//     This driver is intentionally a dumb shuttle: capture path + caller PID,
//     ask user-mode, allow or block. That keeps the kernel surface tiny and
//     lets us iterate detection logic without re-signing the driver.
//
// Status: SCAFFOLD. Compiles with the WDK (see README.md). NOT yet signed.
// To run on production Windows it needs either:
//   * dev: `bcdedit /set testsigning on` + a self-signed cert, OR
//   * prod: an EV code-signing cert + (optionally) WHQL submission via
//     Microsoft Partner Center for attestation/dashboard signing.
//
// Altitude: Microsoft allocates altitudes in the FSFilter Anti-Virus range
// (320000-329999) per ISV. Until we have one assigned we run at a temporary
// dev altitude (385200, "FSFilter Activity Monitor") in the INF. This MUST
// be changed before public release.

#include <fltKernel.h>
#include <dontuse.h>
#include "BastionFilter.h"

#define BASTION_TAG 'BstF'

typedef struct _BASTION_GLOBALS {
    PFLT_FILTER         Filter;
    PFLT_PORT           ServerPort;     // accept user-mode connections
    PFLT_PORT           ClientPort;     // single connected client (the agent)
    PEPROCESS           ClientProcess;  // for unmap of buffers if needed
    KSPIN_LOCK          ClientLock;
} BASTION_GLOBALS, *PBASTION_GLOBALS;

static BASTION_GLOBALS g_State = { 0 };

// Forward decls
DRIVER_INITIALIZE DriverEntry;
NTSTATUS FLTAPI BastionUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS FLTAPI BastionPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);
FLT_POSTOP_CALLBACK_STATUS FLTAPI BastionPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);
NTSTATUS FLTAPI BastionConnect(
    _In_  PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie);
VOID FLTAPI BastionDisconnect(_In_opt_ PVOID ConnectionCookie);

static const FLT_OPERATION_REGISTRATION g_Callbacks[] = {
    { IRP_MJ_CREATE, 0, BastionPreCreate, BastionPostCreate },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION g_Registration = {
    sizeof(FLT_REGISTRATION),       // Size
    FLT_REGISTRATION_VERSION,       // Version
    0,                              // Flags
    NULL,                           // Context
    g_Callbacks,                    // Operation callbacks
    BastionUnload,                  // FilterUnloadCallback
    NULL,                           // InstanceSetup
    NULL,                           // InstanceQueryTeardown
    NULL,                           // InstanceTeardownStart
    NULL,                           // InstanceTeardownComplete
    NULL, NULL, NULL,               // generate file name, normalize, normalize cleanup
    NULL,                           // transaction notification
    NULL,                           // normalize name component ex
    NULL                            // section notification
};

// ----------------------------------------------------------------------------
// DriverEntry
// ----------------------------------------------------------------------------
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    KeInitializeSpinLock(&g_State.ClientLock);

    status = FltRegisterFilter(DriverObject, &g_Registration, &g_State.Filter);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Communication port for user-mode agent.
    UNICODE_STRING portName;
    RtlInitUnicodeString(&portName, BASTION_PORT_NAME);

    OBJECT_ATTRIBUTES oa;
    PSECURITY_DESCRIPTOR sd = NULL;
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) goto fail;

    InitializeObjectAttributes(
        &oa, &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL, sd);

    status = FltCreateCommunicationPort(
        g_State.Filter, &g_State.ServerPort, &oa,
        NULL,               // ServerPortCookie
        BastionConnect,
        BastionDisconnect,
        NULL,               // MessageNotifyCallback (we are kernel->user only)
        1                   // single client
    );
    FltFreeSecurityDescriptor(sd);
    if (!NT_SUCCESS(status)) goto fail;

    status = FltStartFiltering(g_State.Filter);
    if (!NT_SUCCESS(status)) goto fail;

    return STATUS_SUCCESS;

fail:
    if (g_State.ServerPort) FltCloseCommunicationPort(g_State.ServerPort);
    if (g_State.Filter)     FltUnregisterFilter(g_State.Filter);
    return status;
}

NTSTATUS FLTAPI BastionUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    if (g_State.ServerPort) FltCloseCommunicationPort(g_State.ServerPort);
    if (g_State.Filter)     FltUnregisterFilter(g_State.Filter);
    RtlZeroMemory(&g_State, sizeof(g_State));
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
// Communication-port plumbing.
// ----------------------------------------------------------------------------
NTSTATUS FLTAPI BastionConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    KIRQL irql;
    KeAcquireSpinLock(&g_State.ClientLock, &irql);
    g_State.ClientPort = ClientPort;
    g_State.ClientProcess = PsGetCurrentProcess();
    KeReleaseSpinLock(&g_State.ClientLock, irql);

    *ConnectionPortCookie = NULL;
    return STATUS_SUCCESS;
}

VOID FLTAPI BastionDisconnect(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    KIRQL irql;
    KeAcquireSpinLock(&g_State.ClientLock, &irql);
    PFLT_PORT port = g_State.ClientPort;
    g_State.ClientPort = NULL;
    g_State.ClientProcess = NULL;
    KeReleaseSpinLock(&g_State.ClientLock, irql);
    if (port) FltCloseClientPort(g_State.Filter, &port);
}

// ----------------------------------------------------------------------------
// IRP_MJ_CREATE callbacks
// ----------------------------------------------------------------------------
FLT_PREOP_CALLBACK_STATUS FLTAPI BastionPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // Skip kernel-initiated and paging IO; never block those.
    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // We only act post-create (after the open succeeds) so we have a real
    // file we can refer the user-mode scanner to. Returning WITH_CALLBACK
    // lets us run the post-op without holding the IRP here.
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS FLTAPI BastionPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) return FLT_POSTOP_FINISHED_PROCESSING;
    if (!NT_SUCCESS(Data->IoStatus.Status))           return FLT_POSTOP_FINISHED_PROCESSING;
    if (!g_State.ClientPort)                           return FLT_POSTOP_FINISHED_PROCESSING;

    // Build the notify packet on the stack — keep it cheap.
    BASTION_NOTIFY notify = { 0 };
    notify.ProcessId = HandleToULong(PsGetCurrentProcessId());

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS s = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(s)) return FLT_POSTOP_FINISHED_PROCESSING;

    ULONG copyBytes = nameInfo->Name.Length;
    if (copyBytes > sizeof(notify.PathBuffer)) copyBytes = sizeof(notify.PathBuffer);
    RtlCopyMemory(notify.PathBuffer, nameInfo->Name.Buffer, copyBytes);
    notify.PathBytes = copyBytes;
    FltReleaseFileNameInformation(nameInfo);

    // Send to user-mode and wait briefly for a verdict. If the agent isn't
    // running, isn't responding, or times out, FAIL OPEN — better to let
    // the file through than to wedge the entire filesystem.
    BASTION_REPLY reply = { BASTION_VERDICT_ALLOW };
    ULONG replyLen = sizeof(reply);
    LARGE_INTEGER timeout;
    timeout.QuadPart = -10LL * 1000 * 1000 * 2;  // 2 seconds, relative

    NTSTATUS sendStatus = FltSendMessage(
        g_State.Filter,
        &g_State.ClientPort,
        &notify, sizeof(notify),
        &reply,  &replyLen,
        &timeout);

    if (NT_SUCCESS(sendStatus) && reply.Verdict == BASTION_VERDICT_BLOCK) {
        // Tell the I/O manager the open was denied. The handle gets torn down.
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}
