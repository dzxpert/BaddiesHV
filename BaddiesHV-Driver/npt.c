/*
 * npt.c — AMD Nested Page Table identity map builder.
 *
 * Builds a complete identity map (GPA == HPA) of the physical address space
 * using 2MB large pages for performance. RAM regions are mapped WB,
 * everything else (MMIO, APIC, HPET) is mapped UC.
 *
 * Must be called from PASSIVE_LEVEL before subversion.
 *
 * IMPORTANT: All page tables are allocated via MmAllocateContiguousMemory
 * and tracked in NPT_CONTEXT for cleanup.
 */

#include "npt.h"
#include "svm.h"


/* Maximum number of page table pages we might allocate.
 * Worst case: 1 PML4 + 512 PDPT + 512*512 PD = ~262K pages.
 * In practice, physical address space is ~1TB max = ~512 PD tables.
 * We allocate conservatively. */
#define NPT_MAX_PAGES 4096

/* ============================================================================
 * Internal helpers
 * ============================================================================
 */

/*
 * Allocate a zeroed, page-aligned 4KB page for NPT use.
 * Tracks it in the context for cleanup.
 */
static PNPT_ENTRY NptAllocatePage(_Inout_ PNPT_CONTEXT Ctx) {
  if (Ctx->AllocatedPageCount >= Ctx->AllocatedPageMax) {
    return NULL;
  }

  PHYSICAL_ADDRESS lowAddr = {0};
  PHYSICAL_ADDRESS highAddr;
  highAddr.QuadPart = MAXULONG64;
  PHYSICAL_ADDRESS boundary = {0};

  PVOID page = MmAllocateContiguousMemorySpecifyCache(
      PAGE_SIZE, lowAddr, highAddr, boundary, MmCached);
  if (!page) {
    return NULL;
  }

  RtlZeroMemory(page, PAGE_SIZE);

  Ctx->AllocatedPages[Ctx->AllocatedPageCount++] = page;
  return (PNPT_ENTRY)page;
}

/*
 * Get the physical address of a virtual address.
 */
static UINT64 NptVaToPa(PVOID Va) {
  PHYSICAL_ADDRESS pa = MmGetPhysicalAddress(Va);
  return pa.QuadPart;
}

/*
 * Determine if a physical address falls within a RAM range.
 * ranges = array from MmGetPhysicalMemoryRanges, terminated by {0,0}.
 */
static BOOLEAN NptIsRamAddress(UINT64 physAddr, PPHYSICAL_MEMORY_RANGE Ranges) {
  for (UINT32 i = 0; Ranges[i].NumberOfBytes.QuadPart != 0; i++) {
    UINT64 base = Ranges[i].BaseAddress.QuadPart;
    UINT64 end = base + Ranges[i].NumberOfBytes.QuadPart;
    if (physAddr >= base && physAddr < end) {
      return TRUE;
    }
  }
  return FALSE;
}

/* ============================================================================
 * NptBuildIdentityMap — Build a full identity map of physical memory.
 *
 * Strategy:
 *   1. Get RAM ranges from MmGetPhysicalMemoryRanges()
 *   2. Calculate max physical address to know how much to map
 *   3. Allocate PML4
 *   4. For each 2MB region from 0 to max:
 *      - If any byte of the region is RAM → map WB
 *      - Otherwise → map UC (covers MMIO, APIC, HPET, etc.)
 *   5. Store root PML4 PA in context
 * ============================================================================
 */

NTSTATUS NptBuildIdentityMap(_Out_ PNPT_CONTEXT NptCtx) {
  RtlZeroMemory(NptCtx, sizeof(NPT_CONTEXT));

  /* --- Get system RAM ranges --- */
  PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
  if (!ranges) {
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  /* Find max physical address */
  UINT64 maxPhysAddr = 0;
  for (UINT32 i = 0; ranges[i].NumberOfBytes.QuadPart != 0; i++) {
    UINT64 end =
        ranges[i].BaseAddress.QuadPart + ranges[i].NumberOfBytes.QuadPart;
    if (end > maxPhysAddr) {
      maxPhysAddr = end;
    }
  }

  /* Extend to cover common MMIO regions (at least 4GB + some) */
  if (maxPhysAddr < 0x100000000ULL) {
    maxPhysAddr = 0x100000000ULL; /* At least 4GB */
  }

  /* Round up to 2MB boundary */
  maxPhysAddr =
      (maxPhysAddr + NPT_PAGE_SIZE_2MB - 1) & ~(NPT_PAGE_SIZE_2MB - 1);

  /* --- Allocate page tracker --- */
  NptCtx->AllocatedPageMax = NPT_MAX_PAGES;
  NptCtx->AllocatedPages = (PVOID *)ExAllocatePool2(
      POOL_FLAG_NON_PAGED, sizeof(PVOID) * NPT_MAX_PAGES, 'tpNH');
  if (!NptCtx->AllocatedPages) {
    ExFreePool(ranges);
    return STATUS_INSUFFICIENT_RESOURCES;
  }
  RtlZeroMemory(NptCtx->AllocatedPages, sizeof(PVOID) * NPT_MAX_PAGES);
  NptCtx->AllocatedPageCount = 0;

  /* --- Allocate PML4 (root) --- */
  NptCtx->Pml4 = NptAllocatePage(NptCtx);
  if (!NptCtx->Pml4) {
    ExFreePool(NptCtx->AllocatedPages);
    ExFreePool(ranges);
    return STATUS_INSUFFICIENT_RESOURCES;
  }
  NptCtx->Pml4Pa = NptVaToPa(NptCtx->Pml4);

  /* --- Build identity map using 2MB large pages --- */
  NTSTATUS status = STATUS_SUCCESS;

  for (UINT64 gpa = 0; gpa < maxPhysAddr; gpa += NPT_PAGE_SIZE_2MB) {

    UINT32 pml4Idx = (UINT32)NPT_PML4_INDEX(gpa);
    UINT32 pdptIdx = (UINT32)NPT_PDPT_INDEX(gpa);
    UINT32 pdIdx = (UINT32)NPT_PD_INDEX(gpa);

    /* --- Ensure PDPT exists under PML4[pml4Idx] --- */
    PNPT_ENTRY pdpt;
    if (NptCtx->Pml4[pml4Idx] & NPT_PRESENT) {
      /* PDPT already allocated */
      UINT64 pdptPa = NptCtx->Pml4[pml4Idx] & NPT_PFN_MASK;
      PHYSICAL_ADDRESS pa;
      pa.QuadPart = (LONGLONG)pdptPa;
      pdpt = (PNPT_ENTRY)MmGetVirtualForPhysical(pa);
    } else {
      /* Allocate new PDPT */
      pdpt = NptAllocatePage(NptCtx);
      if (!pdpt) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        break;
      }
      NptCtx->Pml4[pml4Idx] = NPT_MAKE_TABLE_ENTRY(NptVaToPa(pdpt));
    }

    /* --- Ensure PD exists under PDPT[pdptIdx] --- */
    PNPT_ENTRY pd;
    if (pdpt[pdptIdx] & NPT_PRESENT) {
      UINT64 pdPa = pdpt[pdptIdx] & NPT_PFN_MASK;
      PHYSICAL_ADDRESS pa;
      pa.QuadPart = (LONGLONG)pdPa;
      pd = (PNPT_ENTRY)MmGetVirtualForPhysical(pa);
    } else {
      pd = NptAllocatePage(NptCtx);
      if (!pd) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        break;
      }
      pdpt[pdptIdx] = NPT_MAKE_TABLE_ENTRY(NptVaToPa(pd));
    }

    /* --- Create 2MB large page PDE --- */
    UINT64 memType = NptIsRamAddress(gpa, ranges) ? NPT_MT_WB : NPT_MT_UC;
    pd[pdIdx] = NPT_MAKE_LARGE_PDE(gpa, memType);
  }

  ExFreePool(ranges);

  if (!NT_SUCCESS(status)) {
    NptDestroyIdentityMap(NptCtx);
    return status;
  }

  return STATUS_SUCCESS;
}

/* ============================================================================
 * NptDestroyIdentityMap — Free all NPT page tables.
 * ============================================================================
 */

VOID NptDestroyIdentityMap(_Inout_ PNPT_CONTEXT NptCtx) {
  if (NptCtx->AllocatedPages) {
    for (UINT32 i = 0; i < NptCtx->AllocatedPageCount; i++) {
      if (NptCtx->AllocatedPages[i]) {
        MmFreeContiguousMemory(NptCtx->AllocatedPages[i]);
        NptCtx->AllocatedPages[i] = NULL;
      }
    }
    ExFreePool(NptCtx->AllocatedPages);
    NptCtx->AllocatedPages = NULL;
  }

  NptCtx->AllocatedPageCount = 0;
  NptCtx->AllocatedPageMax = 0;
  NptCtx->Pml4 = NULL;
  NptCtx->Pml4Pa = 0;
}
