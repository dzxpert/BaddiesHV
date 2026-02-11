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
#include <stdint.h>
#include <windows.h>

/* Map kernel types to usermode equivalents */
typedef uint64_t UINT64;
typedef uint32_t UINT32;
typedef uint8_t UINT8;
typedef int64_t INT64;
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

#define HV_CPUID_LEAF 0xBADD1E5u      /* Magic CPUID leaf for hypercalls   */
#define HV_MAGIC 0xBADD1E5C0DE0000ull /* Magic for request validation */

/* ============================================================================
 * Command IDs  (passed in ECX / subleaf, always 32-bit — no truncation)
 * ============================================================================
 */

#define HV_CMD_REGISTER 0x00 /* Register shared page (init only)      */
#define HV_CMD_PING 0x01     /* Echo test — HV writes result = 1      */
#define HV_CMD_READ 0x02     /* Read process memory                   */
#define HV_CMD_WRITE 0x03    /* Write process memory                  */
#define HV_CMD_GET_CR3 0x04  /* Get DirectoryTableBase for a PID      */
#define HV_CMD_DEVIRT 0xFF   /* Devirtualize all processors (unload)  */

/* Two-step shared page registration via CPUID ECX encoding.
 * MSVC x64 __cpuidex only lets us control EAX and ECX, so we encode
 * the 48-bit shared page VA across two calls using ECX:
 *
 *   Call 1: ECX[7:0] = 0x10 (REGISTER_LO), ECX[31:8] = VA[23:0]
 *   Call 2: ECX[7:0] = 0x11 (REGISTER_HI), ECX[31:8] = VA[47:24]
 *
 * Handler combines them and translates VA → GPA via guest CR3.
 */
#define HV_CMD_REGISTER_LO 0x10 /* Pass VA bits [23:0]  in ECX[31:8]     */
#define HV_CMD_REGISTER_HI 0x11 /* Pass VA bits [47:24] in ECX[31:8]     */

/* ============================================================================
 * Status codes  (written to HV_REQUEST.result by the HV)
 * ============================================================================
 */

#define HV_STATUS_SUCCESS 0x00000000
#define HV_STATUS_INVALID_MAGIC 0x80000001
#define HV_STATUS_INVALID_COMMAND 0x80000002
#define HV_STATUS_INVALID_PID 0x80000003
#define HV_STATUS_PAGE_NOT_RESIDENT 0x80000004
#define HV_STATUS_TRANSLATION_FAIL 0x80000005
#define HV_STATUS_NOT_REGISTERED 0x80000006
#define HV_STATUS_ALREADY_REGISTERED 0x80000007

/* ============================================================================
 * HV_REQUEST — The command structure written to the shared page.
 *
 * Populated by the loader before issuing the CPUID hypercall.
 * The HV reads this from the pre-registered shared page GPA.
 * ============================================================================
 */

typedef struct _HV_REQUEST {
  UINT64 magic;   /* Must equal HV_MAGIC. Prevents accidental CPUID    */
                  /* collisions from random code hitting our leaf.     */
  UINT32 command; /* HV_CMD_* constant                                 */
  UINT32 pid;     /* Target process ID (for READ/WRITE/GET_CR3)        */
  UINT64 address; /* Target virtual address in the guest process       */
  UINT64 size;    /* Number of bytes to read/write                     */
  UINT64 result;  /* HV writes status code here (HV_STATUS_*)         */
} HV_REQUEST;

/* ============================================================================
 * HV_SHARED_PAGE — Allocated by the loader, registered with HV at init.
 *
 * The data buffer is INLINE (not a pointer), so the HV can access it
 * directly via the pre-registered GPA without translating user-mode VAs.
 * Max per-call transfer = HV_DATA_SIZE bytes.
 * ============================================================================
 */

#define HV_SHARED_STATUS_IDLE 0     /* Ready for a new command           */
#define HV_SHARED_STATUS_PENDING 1  /* Command submitted, HV processing  */
#define HV_SHARED_STATUS_COMPLETE 2 /* HV finished, result is valid      */

/* Header: request + status + padding to 128 bytes for alignment */
#define HV_HEADER_SIZE 128
#define HV_DATA_SIZE (4096 - HV_HEADER_SIZE) /* ~3968 bytes per call */

typedef struct _HV_SHARED_PAGE {
  volatile HV_REQUEST request;
  volatile UINT64 status; /* HV_SHARED_STATUS_* enum               */
  UINT8 _pad[HV_HEADER_SIZE - sizeof(HV_REQUEST) - sizeof(UINT64)];
  UINT8 data[HV_DATA_SIZE]; /* Inline R/W buffer — no pointer chasing */
} HV_SHARED_PAGE;

/* Compile-time size validation */
#ifndef _KERNEL_MODE
static_assert(sizeof(HV_SHARED_PAGE) == 4096, "HV_SHARED_PAGE must be 4KB");
static_assert(sizeof(HV_REQUEST) == 40, "HV_REQUEST must be 40 bytes");
#else
C_ASSERT(sizeof(HV_SHARED_PAGE) == 4096);
C_ASSERT(sizeof(HV_REQUEST) == 40);
#endif

#endif /* HVCOMM_H */
