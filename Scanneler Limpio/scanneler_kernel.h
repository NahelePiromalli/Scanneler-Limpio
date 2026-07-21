#ifndef SCANNELER_KERNEL_H
#define SCANNELER_KERNEL_H

/**
 * ============================================================================
 * SCANNELER RING 0 KERNEL DRIVER INTERFACE HEADER
 * ============================================================================
 * Defines shared IOCTL control codes and event structures between Ring 0 (KMDF Driver)
 * and Ring 3 (User-Mode Python Engine via ctypes).
 */

#include <ntddk.h>

#define SCANNELER_DEVICE_TYPE 0x8000

// IOCTL Control Codes (Buffered I/O for safe data transfer)
#define IOCTL_SCANNELER_PING \
    CTL_CODE(SCANNELER_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_SCANNELER_GET_PROCESS_EVENTS \
    CTL_CODE(SCANNELER_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_SCANNELER_CLEAR_EVENTS \
    CTL_CODE(SCANNELER_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

// Structure for Kernel Process Telemetry Events
typedef struct _PROCESS_EVENT_INFO {
    ULONG ProcessId;
    ULONG ParentProcessId;
    BOOLEAN Created;               // TRUE if process created, FALSE if terminated
    WCHAR ImageFileName[260];      // Full image file path from Kernel
} PROCESS_EVENT_INFO, *PPROCESS_EVENT_INFO;

#endif // SCANNELER_KERNEL_H
