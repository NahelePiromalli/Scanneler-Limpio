/**
 * ============================================================================
 * SCANNELER RING 0 KERNEL DRIVER (.SYS)
 * ============================================================================
 * Language: C (WDK / Windows Kernel Driver Framework)
 * Level: Ring 0 (Windows Kernel Mode)
 * Purpose: Real-time process creation monitoring & kernel-level telemetry.
 * ============================================================================
 */

#include <ntddk.h>
#include "scanneler_kernel.h"

#define MAX_EVENT_BUFFER 128

static UNICODE_STRING g_DeviceName = RTL_CONSTANT_STRING(L"\\Device\\ScannelerKernel");
static UNICODE_STRING g_SymbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\ScannelerKernel");

static PROCESS_EVENT_INFO g_EventBuffer[MAX_EVENT_BUFFER];
static ULONG g_EventCount = 0;
static KSPIN_LOCK g_BufferLock;

// ----------------------------------------------------------------------------
// Process Creation Callback (Ring 0 Telemetry)
// ----------------------------------------------------------------------------
VOID ProcessNotifyCallbackEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    UNREFERENCED_PARAMETER(Process);
    KLOCK_QUEUE_HANDLE lockHandle;

    KeAcquireInStackQueuedSpinLock(&g_BufferLock, &lockHandle);

    if (g_EventCount < MAX_EVENT_BUFFER) {
        PPROCESS_EVENT_INFO ev = &g_EventBuffer[g_EventCount];
        ev->ProcessId = (ULONG)(ULONG_PTR)ProcessId;
        
        if (CreateInfo != NULL) {
            // Process Created
            ev->Created = TRUE;
            ev->ParentProcessId = (ULONG)(ULONG_PTR)CreateInfo->ParentProcessId;
            
            if (CreateInfo->ImageFileName != NULL) {
                USHORT copyLen = CreateInfo->ImageFileName->Length;
                if (copyLen > 259 * sizeof(WCHAR)) copyLen = 259 * sizeof(WCHAR);
                RtlCopyMemory(ev->ImageFileName, CreateInfo->ImageFileName->Buffer, copyLen);
                ev->ImageFileName[copyLen / sizeof(WCHAR)] = L'\0';
            } else {
                ev->ImageFileName[0] = L'\0';
            }
        } else {
            // Process Terminated
            ev->Created = FALSE;
            ev->ParentProcessId = 0;
            ev->ImageFileName[0] = L'\0';
        }

        g_EventCount++;
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
}

// ----------------------------------------------------------------------------
// Dispatch Create / Close
// ----------------------------------------------------------------------------
NTSTATUS ScannelerCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
// Dispatch Device Control (IOCTL Handler)
// ----------------------------------------------------------------------------
NTSTATUS ScannelerDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctl = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesReturned = 0;

    switch (ioctl) {
        case IOCTL_SCANNELER_PING:
            if (outLength >= sizeof(ULONG)) {
                *(PULONG)buffer = 0x5343414E; // "SCAN" in HEX
                bytesReturned = sizeof(ULONG);
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;

        case IOCTL_SCANNELER_GET_PROCESS_EVENTS:
        {
            KLOCK_QUEUE_HANDLE lockHandle;
            KeAcquireInStackQueuedSpinLock(&g_BufferLock, &lockHandle);

            ULONG requiredBytes = g_EventCount * sizeof(PROCESS_EVENT_INFO);
            if (outLength >= requiredBytes) {
                RtlCopyMemory(buffer, g_EventBuffer, requiredBytes);
                bytesReturned = requiredBytes;
                g_EventCount = 0; // Clear buffer after reading
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }

            KeReleaseInStackQueuedSpinLock(&lockHandle);
            break;
        }

        case IOCTL_SCANNELER_CLEAR_EVENTS:
        {
            KLOCK_QUEUE_HANDLE lockHandle;
            KeAcquireInStackQueuedSpinLock(&g_BufferLock, &lockHandle);
            g_EventCount = 0;
            KeReleaseInStackQueuedSpinLock(&lockHandle);
            status = STATUS_SUCCESS;
            break;
        }

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// ----------------------------------------------------------------------------
// Driver Unload Handler
// ----------------------------------------------------------------------------
VOID ScannelerUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    // Unregister Ring 0 Process Callback
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, TRUE);

    // Delete Symbolic Link & Device Object
    IoDeleteSymbolicLink(&g_SymbolicLink);
    if (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

// ----------------------------------------------------------------------------
// Driver Entry Point (Ring 0 Initialization)
// ----------------------------------------------------------------------------
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;

    KeInitializeSpinLock(&g_BufferLock);

    // Create Kernel Device Object
    status = IoCreateDevice(
        DriverObject,
        0,
        &g_DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject
    );

    if (!NT_SUCCESS(status)) return status;

    // Create Symbolic Link for User Mode Access
    status = IoCreateSymbolicLink(&g_SymbolicLink, &g_DeviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }

    // Set IRP Handlers
    DriverObject->MajorFunction[IRP_MJ_CREATE] = ScannelerCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]  = ScannelerCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ScannelerDeviceControl;
    DriverObject->DriverUnload = ScannelerUnload;

    // Register Process Notification Callback (Ring 0 Telemetry)
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallbackEx, FALSE);
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&g_SymbolicLink);
        IoDeleteDevice(deviceObject);
        return status;
    }

    return STATUS_SUCCESS;
}
