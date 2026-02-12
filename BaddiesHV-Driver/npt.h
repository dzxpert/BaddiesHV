/*
 * npt.h — AMD Nested Page Table (NPT) structures and API.
 *
 * NPT provides a second stage of address translation:
 *   Guest Virtual → Guest Physical (via guest page tables, CR3)
 *   Guest Physical → Host Physical (via NPT, VMCB.N_CR3)
 *
 * We build an identity map (GPA == HPA) so physical memory access is
 * transparent. NPT violations (#NPF, VMEXIT 0x400) trigger only for
 * unmapped regions or permission violations.
 *
 * Page table layout (same 4-level structure as x86-64):
 *   PML4 → PDPT → PD → PT (or 2MB large page at PD level)
 *
 * Memory types:
 *   RAM ranges → WB (Write-Back) for performance
 *   Everything else (MMIO, APIC, HPET, etc.) → UC (Uncacheable)
 */

#ifndef NPT_H
#define NPT_H

#include <ntifs.h>

/* ============================================================================
 * Guest Page Table Entry Bits (standard x86-64)
 *
 * Used for walking guest page tables (CR3 → PML4 → PDPT → PD → PT).
 * Shared between mem_ops.c and the VMEXIT handler in svm.c.
 * ============================================================================
 */

#define GUEST_PTE_PRESENT (1ULL << 0)
#define GUEST_PTE_WRITE (1ULL << 1)
#define GUEST_PTE_LARGE_PAGE (1ULL << 7)
#define GUEST_PTE_PFN_MASK 0x000FFFFFFFFFF000ULL
#define GUEST_PTE_PFN_MASK_2M 0x000FFFFFFFE00000ULL
#define GUEST_PTE_PFN_MASK_1G 0x000FFFFFC0000000ULL

/* ============================================================================
 * AMD NPT Page Table Entry — Generic 64-bit format
 *
 * AMD APM Vol 2, Table 15-26: Nested Page Table Entry Format
 * Bit layout is identical to standard x86-64 page table entries
 * with AMD-specific interpretations for memory type control.
 * ============================================================================
 */

/* Memory type encoding for NPT entries (PAT-like, bits [5:3] of PTE) */
#define NPT_MT_UC 0x00ULL /* Uncacheable */
#define NPT_MT_WC 0x01ULL /* Write-Combining */
#define NPT_MT_WT 0x04ULL /* Write-Through */
#define NPT_MT_WP 0x05ULL /* Write-Protect */
#define NPT_MT_WB 0x06ULL /* Write-Back */

/* Page sizes */
#define NPT_PAGE_SIZE_4KB 0x1000ULL
#define NPT_PAGE_SIZE_2MB 0x200000ULL
#define NPT_PAGE_SIZE_1GB 0x40000000ULL

/* Number of entries in each level */
#define NPT_ENTRIES_PER_TABLE 512

/* PML4 index covers 48 bits of address space: bits [47:39] */
#define NPT_PML4_INDEX(gpa) (((gpa) >> 39) & 0x1FF)
#define NPT_PDPT_INDEX(gpa) (((gpa) >> 30) & 0x1FF)
#define NPT_PD_INDEX(gpa) (((gpa) >> 21) & 0x1FF)
#define NPT_PT_INDEX(gpa) (((gpa) >> 12) & 0x1FF)

/* ============================================================================
 * NPT Page Table Entry Bits
 * ============================================================================
 */

#define NPT_PRESENT (1ULL << 0)    /* Valid entry */
#define NPT_WRITE (1ULL << 1)      /* Writable */
#define NPT_USER (1ULL << 2)       /* User-accessible (always set for NPT) */
#define NPT_PWT (1ULL << 3)        /* Page-level Write-Through */
#define NPT_PCD (1ULL << 4)        /* Page-level Cache-Disable */
#define NPT_ACCESSED (1ULL << 5)   /* Accessed */
#define NPT_DIRTY (1ULL << 6)      /* Dirty (only valid for leaf entries) */
#define NPT_LARGE_PAGE (1ULL << 7) /* Large page (2MB at PD, 1GB at PDPT) */

/* Physical address mask — bits [51:12] for 4KB entries, [51:21] for 2MB */
#define NPT_PFN_MASK 0x000FFFFFFFFFF000ULL
#define NPT_PFN_MASK_2M 0x000FFFFFFFE00000ULL

/* ============================================================================
 * NPT Entry Type — used as a generic 64-bit value
 *
 * We use a simple UINT64 rather than bit-field unions to keep things
 * clear and avoid C bit-field portability issues.
 * ============================================================================
 */

typedef UINT64 NPT_ENTRY, *PNPT_ENTRY;

/* Helper macros for building NPT entries */

/* Build a PML4E/PDPTE/PDE pointing to the next table level */
#define NPT_MAKE_TABLE_ENTRY(table_pa)                                         \
  ((table_pa) | NPT_PRESENT | NPT_WRITE | NPT_USER)

/* Build a 2MB large page PDE (identity map: GPA == HPA) */
#define NPT_MAKE_LARGE_PDE(gpa, mem_type)                                      \
  ((gpa) | NPT_PRESENT | NPT_WRITE | NPT_USER | NPT_LARGE_PAGE |               \
   NPT_MAKE_MEM_TYPE_2MB(mem_type))

/* Build a 4KB PTE */
#define NPT_MAKE_PTE(gpa, mem_type)                                            \
  ((gpa) | NPT_PRESENT | NPT_WRITE | NPT_USER | NPT_MAKE_MEM_TYPE_4KB(mem_type))

/*
 * Memory type encoding for NPT:
 * For 4KB pages: PAT (bit 7), PCD (bit 4), PWT (bit 3) → index into PAT MSR
 * For 2MB pages: PAT (bit 12), PCD (bit 4), PWT (bit 3)
 *
 * Default PAT MSR on AMD:
 *   Index 0 = WB  (PWT=0, PCD=0, PAT=0)
 *   Index 1 = WT  (PWT=1, PCD=0, PAT=0)
 *   Index 2 = UC- (PWT=0, PCD=1, PAT=0)
 *   Index 3 = UC  (PWT=1, PCD=1, PAT=0)
 *   Index 4 = WB  (PWT=0, PCD=0, PAT=1)
 *   Index 5 = WT  (PWT=1, PCD=0, PAT=1)
 *   Index 6 = UC- (PWT=0, PCD=1, PAT=1)
 *   Index 7 = UC  (PWT=1, PCD=1, PAT=1)
 *
 * For identity map we only need:
 *   WB = index 0 → PWT=0, PCD=0 → no bits set
 *   UC = index 3 → PWT=1, PCD=1
 */
#define NPT_MAKE_MEM_TYPE_4KB(mt)                                              \
  (((mt) == NPT_MT_UC) ? (NPT_PWT | NPT_PCD) : 0ULL)

#define NPT_MAKE_MEM_TYPE_2MB(mt)                                              \
  (((mt) == NPT_MT_UC) ? (NPT_PWT | NPT_PCD) : 0ULL)

/* ============================================================================
 * NPT_CONTEXT — Global NPT state
 *
 * One context per hypervisor instance. The root PML4 physical address
 * is written to each VMCB's NestedCr3 field.
 * ============================================================================
 */

typedef struct _NPT_CONTEXT {
  PNPT_ENTRY Pml4; /* Virtual address of root PML4 table */
  UINT64 Pml4Pa;   /* Physical address of root PML4 table */

  /* Page pool tracking for cleanup */
  PVOID *AllocatedPages;     /* Array of VA pointers for cleanup */
  UINT32 AllocatedPageCount; /* Number of pages allocated */
  UINT32 AllocatedPageMax;   /* Capacity of the array */
} NPT_CONTEXT, *PNPT_CONTEXT;

/* ============================================================================
 * Function Declarations — npt.c
 * ============================================================================
 */

/*
 * NptBuildIdentityMap — Build a full identity map of physical memory.
 *
 * Maps ALL physical addresses from 0 to max:
 *   - RAM ranges (from MmGetPhysicalMemoryRanges) → WB
 *   - Everything else (MMIO, APIC, HPET, reserved) → UC
 *
 * Uses 2MB large pages for performance. Allocates all page tables
 * from nonpaged pool via MmAllocateContiguousMemory.
 *
 * Must be called from PASSIVE_LEVEL (before subversion).
 */
NTSTATUS NptBuildIdentityMap(_Out_ PNPT_CONTEXT NptCtx);

/*
 * NptDestroyIdentityMap — Free all NPT page tables.
 */
VOID NptDestroyIdentityMap(_Inout_ PNPT_CONTEXT NptCtx);

/*
 * NptSplitLargePage — Split a 2MB large page into 512 4KB pages.
 *
 * Allocates a new page table, fills it with 4KB entries mapping the
 * same 2MB range, and updates the PDE to point to the new table.
 */
NTSTATUS NptSplitLargePage(_In_ PNPT_CONTEXT NptCtx, _In_ PNPT_ENTRY Pde,
                           _In_ UINT64 GpaBase);

#endif /* NPT_H */
