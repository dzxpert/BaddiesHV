/*
 * npt_protection.c — NPT-based memory protection implementation.
 *
 * Protects hypervisor structures (VMCB, MSRPM, Host Save Area) from
 * detection by marking their GPAs as non-present in the NPT.
 */

#include "npt_protection.h"
#include "svm.h"

#define HV_LOG(fmt, ...) DbgPrint("[BaddiesHV] " fmt "\n", ##__VA_ARGS__)

#define HV_LOG_ERROR(fmt, ...) DbgPrint("[BaddiesHV][ERROR] " fmt "\n", ##__VA_ARGS__)

/* ============================================================================
 * NptProtectRange — Mark a GPA range as non-present in NPT
 * ============================================================================
 */

NTSTATUS NptProtectRange(_In_ PNPT_CONTEXT NptCtx,
                         _Inout_ PNPT_PROTECTION_CONTEXT ProtCtx,
                         _In_ UINT64 Gpa, _In_ UINT64 Size) {

  if (!NptCtx || !NptCtx->Pml4 || !ProtCtx) {
    return STATUS_INVALID_PARAMETER;
  }

  /* Align range to 4KB boundary */
  UINT64 gpaAligned = Gpa & ~(NPT_PAGE_SIZE_4KB - 1);
  UINT64 endGpa =
      (Gpa + Size + NPT_PAGE_SIZE_4KB - 1) & ~(NPT_PAGE_SIZE_4KB - 1);
  UINT64 sizeAligned = endGpa - gpaAligned;

  HV_LOG("NptProtectRange: GPA 0x%llX size 0x%llX (aligned: 0x%llX - 0x%llX)",
         Gpa, Size, gpaAligned, endGpa);

  /* Track the range */
  if (ProtCtx->RangeCount >= MAX_PROTECTED_RANGES) {
    HV_LOG_ERROR("NptProtectRange: Too many protected ranges (max %u)",
                 MAX_PROTECTED_RANGES);
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  /* Walk NPT and protect each 4KB page */
  for (UINT64 curGpa = gpaAligned; curGpa < endGpa;
       curGpa += NPT_PAGE_SIZE_4KB) {

    UINT32 pml4Idx = (UINT32)NPT_PML4_INDEX(curGpa);
    UINT32 pdptIdx = (UINT32)NPT_PDPT_INDEX(curGpa);
    UINT32 pdIdx = (UINT32)NPT_PD_INDEX(curGpa);
    UINT32 ptIdx = (UINT32)NPT_PT_INDEX(curGpa);

    /* --- Walk to PD level --- */
    PNPT_ENTRY pml4 = NptCtx->Pml4;
    if (!(pml4[pml4Idx] & NPT_PRESENT)) {
      HV_LOG_ERROR("NptProtectRange: PML4[%u] not present for GPA 0x%llX",
                   pml4Idx, curGpa);
      return STATUS_UNSUCCESSFUL;
    }

    UINT64 pdptPa = pml4[pml4Idx] & NPT_PFN_MASK;
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)pdptPa;
    PNPT_ENTRY pdpt = (PNPT_ENTRY)MmGetVirtualForPhysical(pa);
    if (!pdpt || !(pdpt[pdptIdx] & NPT_PRESENT)) {
      HV_LOG_ERROR("NptProtectRange: PDPT[%u] invalid for GPA 0x%llX", pdptIdx,
                   curGpa);
      return STATUS_UNSUCCESSFUL;
    }

    UINT64 pdPa = pdpt[pdptIdx] & NPT_PFN_MASK;
    pa.QuadPart = (LONGLONG)pdPa;
    PNPT_ENTRY pd = (PNPT_ENTRY)MmGetVirtualForPhysical(pa);
    if (!pd) {
      HV_LOG_ERROR("NptProtectRange: Cannot map PD PA 0x%llX", pdPa);
      return STATUS_UNSUCCESSFUL;
    }

    /* --- Check for Large Page (2MB) at PD level --- */
    if (pd[pdIdx] & NPT_LARGE_PAGE) {
      /* Split 2MB page into 4KB pages */
      /* Note: passing 2MB-aligned base for splitting */
      UINT64 largePageBase = curGpa & ~(NPT_PAGE_SIZE_2MB - 1);
      NTSTATUS status = NptSplitLargePage(NptCtx, &pd[pdIdx], largePageBase);
      if (!NT_SUCCESS(status)) {
        HV_LOG_ERROR(
            "NptProtectRange: Failed to split large page at 0x%llX (status=0x%08X)",
            largePageBase, status);
        return status;
      }
    }

    /* --- Walk to PT level --- */
    /* PD entry now points to a Page Table (guaranteed present/alloc'd by split
     * or existing) */
    if (!(pd[pdIdx] & NPT_PRESENT)) {
        /* Should not happen after split/check */
         HV_LOG_ERROR("NptProtectRange: PD[%u] not present after split logic", pdIdx);
         return STATUS_UNSUCCESSFUL;
    }

    UINT64 ptPa = pd[pdIdx] & NPT_PFN_MASK;
    pa.QuadPart = (LONGLONG)ptPa;
    PNPT_ENTRY pt = (PNPT_ENTRY)MmGetVirtualForPhysical(pa);
    if (!pt) {
      HV_LOG_ERROR("NptProtectRange: Cannot map PT PA 0x%llX", ptPa);
      return STATUS_UNSUCCESSFUL;
    }

    /* --- Protect 4KB PTE --- */
    /* Clear PRESENT bit */
    if (pt[ptIdx] & NPT_PRESENT) {
        pt[ptIdx] &= ~NPT_PRESENT;
    }
  }

  /* Record protected range */
  UINT32 idx = ProtCtx->RangeCount++;
  ProtCtx->Ranges[idx].Gpa = gpaAligned;
  ProtCtx->Ranges[idx].Size = sizeAligned;

  return STATUS_SUCCESS;
}

/* ============================================================================
 * NptUnprotectRange — Restore access to a protected range
 * ============================================================================
 */

NTSTATUS NptUnprotectRange(_In_ PNPT_CONTEXT NptCtx,
                           _Inout_ PNPT_PROTECTION_CONTEXT ProtCtx,
                           _In_ UINT64 Gpa) {

  if (!NptCtx || !NptCtx->Pml4 || !ProtCtx) {
    return STATUS_INVALID_PARAMETER;
  }

  /* Align based on our internal usage (4KB) */
  UINT64 gpaAligned = Gpa & ~(NPT_PAGE_SIZE_4KB - 1);

  /* Find the protected range */
  /* Note: Simple search. Could be optimized if needed. */
  for (UINT32 i = 0; i < ProtCtx->RangeCount; i++) {
    if (ProtCtx->Ranges[i].Gpa == gpaAligned) {
      PPROTECTED_RANGE range = &ProtCtx->Ranges[i];
      UINT64 endGpa = range->Gpa + range->Size;

      /* Walk pages and restore PRESENT bit */
      for (UINT64 curGpa = range->Gpa; curGpa < endGpa;
           curGpa += NPT_PAGE_SIZE_4KB) {
        
        UINT32 pml4Idx = (UINT32)NPT_PML4_INDEX(curGpa);
        UINT32 pdptIdx = (UINT32)NPT_PDPT_INDEX(curGpa);
        UINT32 pdIdx = (UINT32)NPT_PD_INDEX(curGpa);
        UINT32 ptIdx = (UINT32)NPT_PT_INDEX(curGpa);

        /* Walk NPT (assume structure exists as we protected it) */
        PNPT_ENTRY pml4 = NptCtx->Pml4;
        UINT64 pdptPa = pml4[pml4Idx] & NPT_PFN_MASK;
        PHYSICAL_ADDRESS pa;
        pa.QuadPart = (LONGLONG)pdptPa;
        PNPT_ENTRY pdpt = (PNPT_ENTRY)MmGetVirtualForPhysical(pa);
        if (!pdpt) continue;

        UINT64 pdPa = pdpt[pdptIdx] & NPT_PFN_MASK;
        pa.QuadPart = (LONGLONG)pdPa;
        PNPT_ENTRY pd = (PNPT_ENTRY)MmGetVirtualForPhysical(pa);
        if (!pd) continue;

        /* We expect a Page Table here now (split) */
        if (pd[pdIdx] & NPT_LARGE_PAGE) {
            /* Should not happen if we split it during protection */
            continue; 
        }

        UINT64 ptPa = pd[pdIdx] & NPT_PFN_MASK;
        pa.QuadPart = (LONGLONG)ptPa;
        PNPT_ENTRY pt = (PNPT_ENTRY)MmGetVirtualForPhysical(pa);
        if (!pt) continue;

        /* Restore PRESENT bit */
        pt[ptIdx] |= NPT_PRESENT;
      }

      HV_LOG("NptUnprotectRange: Restored range at GPA 0x%llX (Size 0x%llX)",
             range->Gpa, range->Size);

      /* Remove from list */
      ProtCtx->Ranges[i] = ProtCtx->Ranges[ProtCtx->RangeCount - 1];
      ProtCtx->RangeCount--;

      return STATUS_SUCCESS;
    }
  }

  return STATUS_NOT_FOUND;
}

/* ============================================================================
 * NptProtectHypervisorStructures — Protect all hypervisor structures
 * ============================================================================
 */

NTSTATUS NptProtectHypervisorStructures(
    _In_ PNPT_CONTEXT NptCtx, _Out_ PNPT_PROTECTION_CONTEXT ProtCtx,
    _In_ PVCPU_DATA *VcpuArray, _In_ UINT32 ProcessorCount,
    _In_ UINT64 MsrpmPa, _In_ UINT64 MsrpmSize) {

  NTSTATUS status;

  if (!NptCtx || !ProtCtx || !VcpuArray) {
    return STATUS_INVALID_PARAMETER;
  }

  RtlZeroMemory(ProtCtx, sizeof(NPT_PROTECTION_CONTEXT));

  HV_LOG("NptProtectHypervisorStructures: Protecting %u CPUs + MSRPM",
         ProcessorCount);

  /* --- Protect MSRPM (global, shared across all CPUs) --- */
  status = NptProtectRange(NptCtx, ProtCtx, MsrpmPa, MsrpmSize);
  if (!NT_SUCCESS(status)) {
    HV_LOG_ERROR("Failed to protect MSRPM at PA 0x%llX (0x%08X)", MsrpmPa,
                 status);
    return status;
  }

  /* --- Protect per-CPU structures --- */
  for (UINT32 i = 0; i < ProcessorCount; i++) {
    PVCPU_DATA vcpu = VcpuArray[i];
    if (!vcpu)
      continue;

    /* Protect Guest VMCB */
    status = NptProtectRange(NptCtx, ProtCtx, vcpu->GuestVmcbPa.QuadPart,
                             sizeof(VMCB));
    if (!NT_SUCCESS(status)) {
      HV_LOG_ERROR("CPU %u: Failed to protect Guest VMCB at PA 0x%llX", i,
                   vcpu->GuestVmcbPa.QuadPart);
      /* Non-fatal — continue protecting other structures */
    }

    /* Protect Host VMCB */
    status = NptProtectRange(NptCtx, ProtCtx, vcpu->HostVmcbPa.QuadPart,
                             sizeof(VMCB));
    if (!NT_SUCCESS(status)) {
      HV_LOG_ERROR("CPU %u: Failed to protect Host VMCB at PA 0x%llX", i,
                   vcpu->HostVmcbPa.QuadPart);
    }

    /* Protect Host Save Area */
    status =
        NptProtectRange(NptCtx, ProtCtx, vcpu->HostSaveAreaPa.QuadPart, PAGE_SIZE);
    if (!NT_SUCCESS(status)) {
      HV_LOG_ERROR("CPU %u: Failed to protect Host Save Area at PA 0x%llX", i,
                   vcpu->HostSaveAreaPa.QuadPart);
    }
  }

  HV_LOG("NptProtectHypervisorStructures: Protected %u ranges",
         ProtCtx->RangeCount);

  return STATUS_SUCCESS;
}

/* ============================================================================
 * NptUnprotectAll — Unprotect all ranges (cleanup)
 * ============================================================================
 */

VOID NptUnprotectAll(_In_ PNPT_CONTEXT NptCtx,
                     _Inout_ PNPT_PROTECTION_CONTEXT ProtCtx) {

  if (!NptCtx || !ProtCtx) {
    return;
  }

  HV_LOG("NptUnprotectAll: Restoring %u protected ranges", ProtCtx->RangeCount);

  while (ProtCtx->RangeCount > 0) {
    PPROTECTED_RANGE range = &ProtCtx->Ranges[ProtCtx->RangeCount - 1];
    
    /* Reuse UnprotectRange logic (inefficient but safe/simple) */
    /* Or inline it to avoid search overhead, but search is checked by index anyway in Unprotect if we pass index?
       No, Unprotect takes GPA. 
       Let's just implement the loop here. */
    
    UINT64 endGpa = range->Gpa + range->Size;
    for (UINT64 curGpa = range->Gpa; curGpa < endGpa; curGpa += NPT_PAGE_SIZE_4KB) {
        UINT32 pml4Idx = (UINT32)NPT_PML4_INDEX(curGpa);
        UINT32 pdptIdx = (UINT32)NPT_PDPT_INDEX(curGpa);
        UINT32 pdIdx = (UINT32)NPT_PD_INDEX(curGpa);
        UINT32 ptIdx = (UINT32)NPT_PT_INDEX(curGpa);

        PNPT_ENTRY pml4 = NptCtx->Pml4;
        if (!pml4) break;
        
        UINT64 pdptPa = pml4[pml4Idx] & NPT_PFN_MASK;
        PHYSICAL_ADDRESS pa; pa.QuadPart = (LONGLONG)pdptPa;
        PNPT_ENTRY pdpt = (PNPT_ENTRY)MmGetVirtualForPhysical(pa);
        if (!pdpt) continue;

        UINT64 pdPa = pdpt[pdptIdx] & NPT_PFN_MASK;
        pa.QuadPart = (LONGLONG)pdPa;
        PNPT_ENTRY pd = (PNPT_ENTRY)MmGetVirtualForPhysical(pa);
        if (!pd) continue;

        if (pd[pdIdx] & NPT_LARGE_PAGE) continue;

        UINT64 ptPa = pd[pdIdx] & NPT_PFN_MASK;
        pa.QuadPart = (LONGLONG)ptPa;
        PNPT_ENTRY pt = (PNPT_ENTRY)MmGetVirtualForPhysical(pa);
        if (!pt) continue;

        pt[ptIdx] |= NPT_PRESENT;
    }

    ProtCtx->RangeCount--;
  }

  HV_LOG("NptUnprotectAll: All ranges restored");
}
