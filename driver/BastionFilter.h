// BastionFilter.h
// Shared types between the kernel minifilter and the user-mode agent bridge.
// Keep this file pure C / no Windows-only headers so the Rust side can
// translate the layout with `#[repr(C)]` mirrors.

#pragma once

#define BASTION_PORT_NAME L"\\BastionPort"

// Maximum NT-namespace path we'll ship up to user-mode in one message.
// 1024 wchars = 2048 bytes is well above the longest legitimate file path.
#define BASTION_MAX_PATH_WCHARS 1024

// Message FROM driver TO user-mode.
typedef struct _BASTION_NOTIFY {
    unsigned long  ProcessId;     // creator process
    unsigned long  PathBytes;     // valid bytes in PathBuffer (UTF-16, no NUL)
    wchar_t        PathBuffer[BASTION_MAX_PATH_WCHARS];
} BASTION_NOTIFY, *PBASTION_NOTIFY;

// Reply FROM user-mode TO driver.
typedef struct _BASTION_REPLY {
    unsigned long  Verdict;       // 0 = allow, 1 = block
} BASTION_REPLY, *PBASTION_REPLY;

#define BASTION_VERDICT_ALLOW 0u
#define BASTION_VERDICT_BLOCK 1u
