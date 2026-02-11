/*
 * hvcomm.h — Shared hypercall protocol between BaddiesHV driver and loader.
 *
 * This header is included by BOTH the kernel driver (BaddiesHV-Driver) and 
 * the usermode loader (BaddiesHV-Loader). It defines the magic CPUID leaf,
 * command IDs, request structure, and shared page layout.
 *
 * Communication uses a magic CPUID leaf (not VMMCALL) to avoid EFER.SVME
 * detection vectors. See implementation_plan.md for rationale.
 */

#ifndef HVCOMM_H
#define HVCOMM_H

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <stdint.h>
/* Map kernel types to usermode equivalents */
typedef uint64_t UINT64;
typedef uint32_t UINT32;
typedef uint8_t  UINT8;
typedef int64_t  INT64;
#endif

/* ============================================================================
 * CPUID Hypercall Interface
 * ============================================================================
 *
 * Usermode calls:
 *   __cpuidex(regs, HV_CPUID_LEAF, command)
 *
 * The HV intercepts CPUID leaf 0xBADD1E5 via the CPUID filter bitmap.
 * ECX (subleaf) carries the 32-bit command ID — never a pointer, so no
 * truncation issues. Data is exchanged via a pre-registered shared page.
 *
 * Registration flow (once at loader init):
 *   1. Loader allocates HV_SHARED_PAGE via VirtualAlloc
 *   2. Loader issues __cpuidex(regs, HV_CPUID_LEAF, HV_CMD_REGISTER)
 *      with the shared page VA in the request embedded in regs
 *   3. HV translates the VA via caller's CR3 → caches the GPA
 *   4. All subsequent commands read/write via the cached shared page GPA
 *
 * This avoids passing 64-bit pointers through __cpuidex's 32-bit ECX arg.
 */

#define HV_CPUID_LEAF       0xBADD1E5u  /* Magic CPUID leaf for hypercalls   */
#define HV_MAGIC            0xBADD1E5C0DE0000ull /* Magic for request validation */

/* ============================================================================
 * Command IDs  (passed in ECX / subleaf, always 32-bit — no truncation)
 * ============================================================================ */

#define HV_CMD_REGISTER     0x00    /* Register shared page (init only)      */
#define HV_CMD_PING         0x01    /* Echo test — HV writes result = 1      */
#define HV_CMD_READ         0x02    /* Read process memory                   */
#define HV_CMD_WRITE        0x03    /* Write process memory                  */
#define HV_CMD_GET_CR3      0x04    /* Get DirectoryTableBase for a PID      */
#define HV_CMD_DEVIRT       0xFF    /* Devirtualize all processors (unload)  */

/* ============================================================================
 * Status codes  (written to HV_REQUEST.result by the HV)
 * ============================================================================ */

#define HV_STATUS_SUCCESS           0x00000000
#define HV_STATUS_INVALID_MAGIC     0x80000001
#define HV_STATUS_INVALID_COMMAND   0x80000002
#define HV_STATUS_INVALID_PID       0x80000003
#define HV_STATUS_PAGE_NOT_RESIDENT 0x80000004
#define HV_STATUS_TRANSLATION_FAIL  0x80000005
#define HV_STATUS_NOT_REGISTERED    0x80000006
#define HV_STATUS_ALREADY_REGISTERED 0x80000007

/* ============================================================================
 * HV_REQUEST — The command structure written to the shared page.
 *
 * Populated by the loader before issuing the CPUID hypercall.
 * The HV reads this from the pre-registered shared page GPA.
 * ============================================================================ */

typedef struct _HV_REQUEST {
    UINT64  magic;      /* Must equal HV_MAGIC. Prevents accidental CPUID    */
                        /* collisions from random code hitting our leaf.     */
    UINT32  command;    /* HV_CMD_* constant                                 */
    UINT32  pid;        /* Target process ID (for READ/WRITE/GET_CR3)        */
    UINT64  address;    /* Target virtual address in the guest process       */
    UINT64  buffer;     /* Usermode buffer VA — HV translates via caller CR3 */
    UINT64  size;       /* Number of bytes to read/write                     */
    UINT64  result;     /* HV writes status code here (HV_STATUS_*)         */
} HV_REQUEST;

/* ============================================================================
 * HV_SHARED_PAGE — Allocated by the loader, registered with HV at init.
 *
 * This is the communication channel. The loader writes an HV_REQUEST into
 * the `request` field, issues a CPUID hypercall, and reads the result back
 * from `request.result` and/or `status`.
 *
 * The HV caches the GPA of this page at registration time, so it never
 * needs to translate a 64-bit VA from a 32-bit register again.
 * ============================================================================ */

#define HV_SHARED_STATUS_IDLE       0   /* Ready for a new command           */
#define HV_SHARED_STATUS_PENDING    1   /* Command submitted, HV processing  */
#define HV_SHARED_STATUS_COMPLETE   2   /* HV finished, result is valid      */

typedef struct _HV_SHARED_PAGE {
    volatile HV_REQUEST request;
    volatile UINT64     status;     /* HV_SHARED_STATUS_* enum               */
    UINT64              reserved[6]; /* Pad to cache line boundary (64 bytes)*/
} HV_SHARED_PAGE;

/* Compile-time size validation */
#ifndef _KERNEL_MODE
static_assert(sizeof(HV_REQUEST) == 48, "HV_REQUEST must be 48 bytes");
#else
C_ASSERT(sizeof(HV_REQUEST) == 48);
#endif

#endif /* HVCOMM_H */
