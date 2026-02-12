/*
 * npt_protection.h — NPT-based memory protection for hypervisor structures.
 *
 * Prevents anti-cheat systems (e.g., EasyAntiCheat) from detecting the
 * hypervisor by scanning physical memory for VMCB/MSRPM/IOPM signatures.
 *
 * Strategy:
 *   1. After building the identity map, mark hypervisor structure GPAs
 *      as non-present in the NPT (clear NPT_PRESENT bit)
 *   2. Guest OS and anti-cheat cannot access these pages (triggers #NPF)
 *   3. #NPF handler logs the access and injects #PF into guest
 *
 * IMPORTANT: Must be called BEFORE launching VMs (before SvmLaunchVm).
 */

#ifndef NPT_PROTECTION_H
#define NPT_PROTECTION_H

#include "npt.h"

/* Forward declarations to avoid circular dependency with svm.h */
typedef struct _VCPU_DATA VCPU_DATA, *PVCPU_DATA;

/* ============================================================================
 * Protection Context — Tracks protected ranges for cleanup
 * ============================================================================
 */

#define MAX_PROTECTED_RANGES 256

typedef struct _PROTECTED_RANGE {
  UINT64 Gpa;  /* Start GPA of protected range */
  UINT64 Size; /* Size in bytes */
} PROTECTED_RANGE, *PPROTECTED_RANGE;

typedef struct _NPT_PROTECTION_CONTEXT {
  PROTECTED_RANGE Ranges[MAX_PROTECTED_RANGES];
  UINT32 RangeCount;
} NPT_PROTECTION_CONTEXT, *PNPT_PROTECTION_CONTEXT;

/* ============================================================================
 * Function Declarations
 * ============================================================================
 */

/*
 * NptProtectRange — Mark a GPA range as non-present in the NPT.
 *
 * Walks the NPT page tables and clears the NPT_PRESENT bit for all
 * 2MB pages covering [Gpa, Gpa+Size). Backs up original PDEs for unprotect.
 *
 * Parameters:
 *   NptCtx — NPT context (contains PML4 root)
 *   ProtCtx — Protection context (tracks protected ranges)
 *   Gpa — Start guest physical address (will be aligned down to 2MB)
 *   Size — Size in bytes (will be aligned up to 2MB)
 *
 * Returns:
 *   STATUS_SUCCESS if all pages protected
 *   STATUS_INSUFFICIENT_RESOURCES if too many ranges
 *   STATUS_UNSUCCESSFUL if NPT walk fails
 */
NTSTATUS NptProtectRange(_In_ PNPT_CONTEXT NptCtx,
                         _Inout_ PNPT_PROTECTION_CONTEXT ProtCtx,
                         _In_ UINT64 Gpa, _In_ UINT64 Size);

/*
 * NptUnprotectRange — Restore access to a protected GPA range.
 *
 * Restores the original PDE values backed up during NptProtectRange.
 * Used during cleanup (driver unload).
 */
NTSTATUS NptUnprotectRange(_In_ PNPT_CONTEXT NptCtx,
                           _Inout_ PNPT_PROTECTION_CONTEXT ProtCtx,
                           _In_ UINT64 Gpa);

/*
 * NptProtectHypervisorStructures — Protect all hypervisor structures.
 *
 * Protects:
 *   - VMCB for each CPU (guest + host)
 *   - Host Save Area for each CPU
 *   - Global MSRPM (8KB)
 *
 * Must be called AFTER NptBuildIdentityMap and BEFORE SvmSubvertAllProcessors.
 *
 * Parameters:
 *   NptCtx — NPT context
 *   ProtCtx — Protection context (output)
 *   VcpuArray — Array of VCPU_DATA pointers
 *   ProcessorCount — Number of processors
 *   MsrpmPa — Physical address of MSRPM
 *   MsrpmSize — Size of MSRPM (8KB)
 *
 * Returns:
 *   STATUS_SUCCESS if all structures protected
 *   Error code on failure (non-fatal — hypervisor still works)
 */
NTSTATUS NptProtectHypervisorStructures(
    _In_ PNPT_CONTEXT NptCtx, _Out_ PNPT_PROTECTION_CONTEXT ProtCtx,
    _In_ PVCPU_DATA *VcpuArray, _In_ UINT32 ProcessorCount,
    _In_ UINT64 MsrpmPa, _In_ UINT64 MsrpmSize);

/*
 * NptUnprotectAll — Unprotect all ranges (cleanup).
 *
 * Called during driver unload to restore NPT to original state.
 */
VOID NptUnprotectAll(_In_ PNPT_CONTEXT NptCtx,
                     _Inout_ PNPT_PROTECTION_CONTEXT ProtCtx);

#endif /* NPT_PROTECTION_H */
