/*
 * mem_ops.c — Hypervisor memory operations: VA translation, CR3 cache,
 *             and stealth read/write primitives.
 *
 * CRITICAL: All functions in this file run inside the VMEXIT handler
 * with GIF=0. They must use ZERO kernel API calls.
 *
 * All memory access is done via the identity-mapped NPT (GPA == HPA):
 *   1. Walk guest page tables using guest CR3
 *   2. Get the GPA (== HPA in our identity map)
 *   3. Map the HPA to a VA via MmGetVirtualForPhysical (ok during init)
 *      or use direct physical access via __movsb from identity-mapped VA
 *
 * Since our NPT maps GPA→HPA as identity, and the host also runs with
 * the physical→virtual mapping from Windows, we can access any GPA
 * by converting it to a VA via the identity map.
 */

#include "svm.h"

/* Page table index macros for guest VA */
#define GUEST_PML4_INDEX(va) (((va) >> 39) & 0x1FF)
#define GUEST_PDPT_INDEX(va) (((va) >> 30) & 0x1FF)
#define GUEST_PD_INDEX(va) (((va) >> 21) & 0x1FF)
#define GUEST_PT_INDEX(va) (((va) >> 12) & 0x1FF)

/* ============================================================================
 * HvTranslateGuestVa — Translate a guest VA to GPA via manual page table walk.
 *
 * Walks the 4-level x86-64 page table hierarchy (PML4 → PDPT → PD → PT)
 * using MmGetVirtualForPhysical to access each level.  This is safe in
 * VMEXIT context (GIF=0) because:
 *   - We start from CR3 which is already a physical address
 *   - MmGetVirtualForPhysical returns always-resident kernel VAs
 *   - No page faults possible at any step
 *
 * Previous approach (MmGetPhysicalAddress under CR3 swap) could page-fault
 * if PTE pages themselves were paged out.
 * ============================================================================
 */

static NTSTATUS HvTranslateGuestVa(_In_ UINT64 GuestCr3, _In_ UINT64 GuestVa,
                                   _Out_ PUINT64 GuestPa) {

  *GuestPa = 0;

  /* Extract page table indices from the virtual address */
  UINT64 pml4Index = (GuestVa >> 39) & 0x1FF;
  UINT64 pdptIndex = (GuestVa >> 30) & 0x1FF;
  UINT64 pdIndex = (GuestVa >> 21) & 0x1FF;
  UINT64 ptIndex = (GuestVa >> 12) & 0x1FF;
  UINT64 pageOffset = GuestVa & 0xFFF;

  /* CR3 holds the physical address of PML4 (mask out flags in low bits) */
  UINT64 pml4Pa = GuestCr3 & ~0xFFFULL;

  /* Level 4: PML4 */
  PHYSICAL_ADDRESS phys;
  phys.QuadPart = (LONGLONG)(pml4Pa + pml4Index * 8);
  volatile UINT64 *pml4e = (volatile UINT64 *)MmGetVirtualForPhysical(phys);
  if (!pml4e)
    return STATUS_UNSUCCESSFUL;

  UINT64 pml4eVal = *pml4e;
  if (!(pml4eVal & 1)) /* Present bit */
    return STATUS_UNSUCCESSFUL;

  /* Level 3: PDPT */
  UINT64 pdptPa = pml4eVal & 0x000FFFFFFFFFF000ULL;
  phys.QuadPart = (LONGLONG)(pdptPa + pdptIndex * 8);
  volatile UINT64 *pdpte = (volatile UINT64 *)MmGetVirtualForPhysical(phys);
  if (!pdpte)
    return STATUS_UNSUCCESSFUL;

  UINT64 pdpteVal = *pdpte;
  if (!(pdpteVal & 1))
    return STATUS_UNSUCCESSFUL;

  /* Check for 1GB huge page (PS bit) */
  if (pdpteVal & 0x80) {
    *GuestPa = (pdpteVal & 0x000FFFFFC0000000ULL) | (GuestVa & 0x3FFFFFFF);
    return STATUS_SUCCESS;
  }

  /* Level 2: PD */
  UINT64 pdPa = pdpteVal & 0x000FFFFFFFFFF000ULL;
  phys.QuadPart = (LONGLONG)(pdPa + pdIndex * 8);
  volatile UINT64 *pde = (volatile UINT64 *)MmGetVirtualForPhysical(phys);
  if (!pde)
    return STATUS_UNSUCCESSFUL;

  UINT64 pdeVal = *pde;
  if (!(pdeVal & 1))
    return STATUS_UNSUCCESSFUL;

  /* Check for 2MB large page (PS bit) */
  if (pdeVal & 0x80) {
    *GuestPa = (pdeVal & 0x000FFFFFFFE00000ULL) | (GuestVa & 0x1FFFFF);
    return STATUS_SUCCESS;
  }

  /* Level 1: PT */
  UINT64 ptPa = pdeVal & 0x000FFFFFFFFFF000ULL;
  phys.QuadPart = (LONGLONG)(ptPa + ptIndex * 8);
  volatile UINT64 *pte = (volatile UINT64 *)MmGetVirtualForPhysical(phys);
  if (!pte)
    return STATUS_UNSUCCESSFUL;

  UINT64 pteVal = *pte;
  if (!(pteVal & 1))
    return STATUS_UNSUCCESSFUL;

  *GuestPa = (pteVal & 0x000FFFFFFFFFF000ULL) | pageOffset;
  return STATUS_SUCCESS;
}

/* ============================================================================
 * CR3 Cache — Find DirectoryTableBase for a PID
 *
 * Walks the EPROCESS linked list in guest physical memory.
 * Caches results to avoid repeated walks.
 *
 * EPROCESS offsets for Windows 10/11 22H2 (build 22621):
 *   ActiveProcessLinks: 0x448
 *   UniqueProcessId:    0x440
 *   DirectoryTableBase: 0x028
 *
 * These are version-specific. For production, use dynamic offset discovery.
 * ============================================================================
 */

/*
 * EPROCESS/KTHREAD/KPRCB offsets are now discovered dynamically at runtime
 * via offset_discovery.c and stored in g_HvData.Offsets.
 * This allows the hypervisor to work across multiple Windows builds.
 */

/*
 * Read a UINT64 from guest physical address.
 * Uses identity map (GPA == HPA → MmGetVirtualForPhysical).
 */
static UINT64 ReadGuestPhys64(UINT64 Gpa) {
  PHYSICAL_ADDRESS pa;
  pa.QuadPart = (LONGLONG)Gpa;
  volatile UINT64 *va = (volatile UINT64 *)MmGetVirtualForPhysical(pa);
  if (!va)
    return 0;
  return *va;
}

/*
 * Read a UINT32 from guest physical address.
 */
static UINT32 ReadGuestPhys32(UINT64 Gpa) {
  PHYSICAL_ADDRESS pa;
  pa.QuadPart = (LONGLONG)Gpa;
  volatile UINT32 *va = (volatile UINT32 *)MmGetVirtualForPhysical(pa);
  if (!va)
    return 0;
  return *va;
}

/*
 * ReadKernelVa64 — Read a UINT64 from a kernel VA (SAFE version).
 *
 * OLD APPROACH (unsafe):
 *   - Swap to guest CR3, dereference pointer, swap back
 *   - RISK: Page fault if kernel VA is paged out → BSOD at DISPATCH_LEVEL
 *
 * NEW APPROACH (safe):
 *   - Translate KernelVa → GPA via guest page tables (HvTranslateGuestVa)
 *   - Map GPA → host VA via MmGetVirtualForPhysical (always resident)
 *   - Read from host VA (no page fault possible)
 *
 * This is safe because:
 *   - HvTranslateGuestVa walks page tables via MmGetVirtualForPhysical
 *   - MmGetVirtualForPhysical returns always-resident kernel VAs
 *   - No CR3 swap = no risk of accessing paged-out memory
 */
static UINT64 ReadKernelVa64(UINT64 GuestCr3, UINT64 HostCr3, UINT64 KernelVa) {
  UNREFERENCED_PARAMETER(HostCr3); /* No longer needed */

  /* Reject non-kernel addresses to prevent page faults on garbage pointers */
  if (KernelVa < 0xFFFF800000000000ULL)
    return 0;

  /* Translate KernelVa → GPA via guest page tables */
  UINT64 gpa;
  NTSTATUS status = HvTranslateGuestVa(GuestCr3, KernelVa, &gpa);
  if (!NT_SUCCESS(status))
    return 0;

  /* Map GPA → host VA (always safe, no page faults) */
  PHYSICAL_ADDRESS pa;
  pa.QuadPart = (LONGLONG)gpa;
  volatile UINT64 *va = (volatile UINT64 *)MmGetVirtualForPhysical(pa);
  if (!va)
    return 0;

  return *va;
}

/*
 * HvCacheCr3 — Look up CR3 for a given PID.
 *
 * Reads kernel structures (KPCR → KTHREAD → EPROCESS linked list)
 * using the two-phase ReadKernelVa64 helper.
 *
 * Safe because:
 *   - GIF=0: no interrupts
 *   - Kernel mappings are identical in all CR3s
 *   - Only proven-working APIs used (MmGetPhysicalAddress,
 * MmGetVirtualForPhysical)
 */
NTSTATUS HvCacheCr3(_In_ PVCPU_DATA Vcpu, _In_ UINT32 Pid,
                    _Out_ PUINT64 Cr3Out) {

  *Cr3Out = 0;

  /* Check cache first */
  for (UINT32 i = 0; i < Vcpu->Cr3CacheCount; i++) {
    if (Vcpu->Cr3Cache[i].Pid == Pid) {
      *Cr3Out = Vcpu->Cr3Cache[i].Cr3;
      return STATUS_SUCCESS;
    }
  }

  UINT64 guestCr3 = Vcpu->GuestVmcb->StateSave.Cr3;
  UINT64 hostCr3 = __readcr3();

  /* GS.Base (KernelGsBase holds KPCR when guest is in user mode) */
  UINT64 kpcrVa = Vcpu->GuestVmcb->StateSave.KernelGsBase;
  if (kpcrVa == 0)
    kpcrVa = Vcpu->GuestVmcb->StateSave.Gs.Base;

  if (kpcrVa == 0)
    return STATUS_UNSUCCESSFUL;

  /* KPCR + KPRCB.CurrentThread (dynamic offset) */
  UINT64 currentThreadVa = ReadKernelVa64(guestCr3, hostCr3, 
                                           kpcrVa + g_HvData.Offsets.KprcbCurrentThread);
  if (currentThreadVa == 0)
    return STATUS_UNSUCCESSFUL;

  /* KTHREAD.ApcState.Process (dynamic offset) */
  UINT64 currentProcessVa =
      ReadKernelVa64(guestCr3, hostCr3, 
                     currentThreadVa + g_HvData.Offsets.KthreadApcState + 0x20);
  if (currentProcessVa == 0)
    return STATUS_UNSUCCESSFUL;

  /* Walk ActiveProcessLinks starting from current EPROCESS */
  UINT64 headProcessVa = currentProcessVa;
  UINT64 walkProcessVa = currentProcessVa;
  UINT32 maxIterations = 4096;

  do {
    /* Read UniqueProcessId (dynamic offset) */
    UINT64 procPid = ReadKernelVa64(guestCr3, hostCr3,
                                    walkProcessVa + g_HvData.Offsets.EprocessUniqueProcessId);

    if ((UINT32)procPid == Pid) {
      /* Found it! Read DirectoryTableBase (dynamic offset) */
      UINT64 cr3 = ReadKernelVa64(
          guestCr3, hostCr3, walkProcessVa + g_HvData.Offsets.EprocessDirectoryTableBase);

      *Cr3Out = cr3;

      /* Cache it */
      if (Vcpu->Cr3CacheCount < CR3_CACHE_MAX_ENTRIES) {
        UINT32 idx = Vcpu->Cr3CacheCount++;
        Vcpu->Cr3Cache[idx].Pid = Pid;
        Vcpu->Cr3Cache[idx].Cr3 = cr3;
        Vcpu->Cr3Cache[idx].EprocessVa = walkProcessVa;
      }

      return STATUS_SUCCESS;
    }

    /* Follow ActiveProcessLinks.Flink (dynamic offset) */
    UINT64 flink = ReadKernelVa64(
        guestCr3, hostCr3, walkProcessVa + g_HvData.Offsets.EprocessActiveProcessLinks);
    if (flink == 0)
      break;

    /* flink points to the LIST_ENTRY inside the next EPROCESS.
     * Subtract ACTIVE_PROCESS_LINKS offset to get EPROCESS base. */
    walkProcessVa = flink - g_HvData.Offsets.EprocessActiveProcessLinks;

  } while (walkProcessVa != headProcessVa && --maxIterations > 0);

  return STATUS_NOT_FOUND;
}

/* ============================================================================
 * HvReadProcessMemory — Read bytes from a guest process's virtual memory.
 *
 * Swaps to the target process's CR3 and reads directly from the guest VA
 * into DataBuffer (kernel stack — accessible from any CR3).
 * ============================================================================
 */

NTSTATUS
HvReadProcessMemory(_In_ PVCPU_DATA Vcpu, _In_ UINT32 Pid, _In_ UINT64 GuestVa,
                    _Out_writes_bytes_(Size) volatile UINT8 *DataBuffer,
                    _In_ UINT64 Size) {

  if (Size == 0 || !DataBuffer)
    return STATUS_SUCCESS;

  UINT64 targetCr3;
  NTSTATUS status = HvCacheCr3(Vcpu, Pid, &targetCr3);
  if (!NT_SUCCESS(status))
    return status;

  /* BUG FIX: Use HvTranslateGuestVa + MmGetVirtualForPhysical instead of
   * raw CR3 swap with direct dereference.
   *
   * Why the old approach crashes:
   *   __writecr3(targetCr3); ptr dereference;
   *   If the target page is demand-zeroed or paged out, the hardware raises
   *   a page fault. At DIRQL/GIF=0 there is no page fault handler —
   *   the CPU triple-faults and the system reboots.
   *
   * New approach: walk guest page tables (always-resident MmGetVirtualForPhysical
   * on PTE pages) to get the physical address, then map it via
   * MmGetVirtualForPhysical to get a kernel VA that is always resident.
   * No page fault is possible at any step. */
  for (UINT64 i = 0; i < Size; ) {
    UINT64 srcVa  = GuestVa + i;
    UINT64 pageOff = srcVa & 0xFFF;
    UINT64 chunk   = 0x1000 - pageOff; /* bytes remaining in this 4KB page */
    if (chunk > (Size - i))
      chunk = Size - i;

    UINT64 gpa;
    status = HvTranslateGuestVa(targetCr3, srcVa, &gpa);
    if (!NT_SUCCESS(status))
      return STATUS_UNSUCCESSFUL;

    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)gpa;
    volatile UINT8 *hostVa = (volatile UINT8 *)MmGetVirtualForPhysical(pa);
    if (!hostVa)
      return STATUS_UNSUCCESSFUL;

    for (UINT64 j = 0; j < chunk; j++)
      DataBuffer[i + j] = hostVa[j];

    i += chunk;
  }
  return STATUS_SUCCESS;
}

/* ============================================================================
 * HvWriteProcessMemory — Write bytes into a guest process's virtual memory.
 *
 * Swaps to the target process's CR3 and writes directly from DataBuffer
 * (kernel stack) into the guest VA.
 * ============================================================================
 */

NTSTATUS HvWriteProcessMemory(_In_ PVCPU_DATA Vcpu, _In_ UINT32 Pid,
                              _In_ UINT64 GuestVa,
                              _In_reads_bytes_(Size) volatile UINT8 *DataBuffer,
                              _In_ UINT64 Size) {

  if (Size == 0 || !DataBuffer)
    return STATUS_SUCCESS;

  UINT64 targetCr3;
  NTSTATUS status = HvCacheCr3(Vcpu, Pid, &targetCr3);
  if (!NT_SUCCESS(status))
    return status;

  /* BUG FIX: Same rationale as HvReadProcessMemory — use page-table walk
   * instead of raw CR3 swap to prevent BSOD on not-resident pages. */
  for (UINT64 i = 0; i < Size; ) {
    UINT64 dstVa   = GuestVa + i;
    UINT64 pageOff = dstVa & 0xFFF;
    UINT64 chunk   = 0x1000 - pageOff;
    if (chunk > (Size - i))
      chunk = Size - i;

    UINT64 gpa;
    status = HvTranslateGuestVa(targetCr3, dstVa, &gpa);
    if (!NT_SUCCESS(status))
      return STATUS_UNSUCCESSFUL;

    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)gpa;
    volatile UINT8 *hostVa = (volatile UINT8 *)MmGetVirtualForPhysical(pa);
    if (!hostVa)
      return STATUS_UNSUCCESSFUL;

    for (UINT64 j = 0; j < chunk; j++)
      hostVa[j] = DataBuffer[i + j];

    i += chunk;
  }
  return STATUS_SUCCESS;
}

/* ============================================================================
 * HvFindModuleBase — Find a loaded module's base address in a target process.
 *
 * Walks the PEB → Ldr → InMemoryOrderModuleList via CR3 swap.
 * Matches modules by djb2 hash of the lowercase module name.
 *
 * Windows 10/11 22H2 offsets:
 *   EPROCESS + 0x550 = PEB (Wow64Process at 0x448, but we target x64)
 *   PEB + 0x18 = Ldr (PEB_LDR_DATA*)
 *   PEB_LDR_DATA + 0x20 = InMemoryOrderModuleList (LIST_ENTRY)
 *   LDR_DATA_TABLE_ENTRY:
 *     +0x00 = InMemoryOrderLinks (LIST_ENTRY -- relative to this field)
 *     +0x20 = DllBase
 *     +0x48 = BaseDllName (UNICODE_STRING: Length, MaxLength, Buffer)
 *
 * All reads are done under CR3 swap — zero kernel API calls.
 * ============================================================================
 */

/* Note: PEB offset formerly hardcoded here as 0x550 was WRONG (actual = 0x520
 * on Win10/11 22H2). All callers now use g_HvData.Offsets.EprocessPeb which
 * is discovered dynamically at boot via offset_discovery.c. */

static UINT64 Djb2HashWide(UINT64 cr3, UINT64 hostCr3, UINT64 bufferVa,
                           UINT32 lengthBytes) {
  UINT64 hash = 5381;
  UINT32 charCount = lengthBytes / sizeof(UINT16);
  if (charCount > 128)
    charCount = 128;

  /* BUG FIX: Replace raw CR3 swap with HvTranslateGuestVa + MmGetVirtualForPhysical.
   * The UNICODE_STRING.Buffer pointer is a user-mode VA. If the page is not
   * physically resident a raw dereference under CR3 swap causes a triple fault.
   * We walk the string one UINT16 at a time, translating each VA to a kernel VA. */
  for (UINT32 i = 0; i < charCount; i++) {
    UINT64 wchVa = bufferVa + (UINT64)i * sizeof(UINT16);
    UINT64 gpa;
    if (!NT_SUCCESS(HvTranslateGuestVa(cr3, wchVa, &gpa)))
      break;
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)gpa;
    volatile UINT16 *va = (volatile UINT16 *)MmGetVirtualForPhysical(pa);
    if (!va)
      break;
    UINT16 wch = *va;
    if (wch >= L'A' && wch <= L'Z')
      wch += 32;
    hash = ((hash << 5) + hash) + (UINT64)wch;
  }
  UNREFERENCED_PARAMETER(hostCr3); /* no longer needed */
  return hash;
}

/* Debug struct for PEB walk dump: 16 bytes per entry */
typedef struct _MODULE_DEBUG_ENTRY {
  UINT64 hash;
  UINT64 base;
} MODULE_DEBUG_ENTRY;

NTSTATUS HvFindModuleBase(_In_ PVCPU_DATA Vcpu, _In_ UINT32 Pid,
                          _In_ UINT64 ModuleNameHash, _Out_ PUINT64 BaseOut,
                          _Out_opt_ UINT8 *DebugBuf, _In_ UINT32 DebugBufSize,
                          _In_ UINT64 SharedPageCr3) {

  *BaseOut = 0;

  /* Get target CR3 and EPROCESS VA */
  UINT64 targetCr3;
  NTSTATUS status = HvCacheCr3(Vcpu, Pid, &targetCr3);
  if (!NT_SUCCESS(status))
    return status;

  /* Find cached EPROCESS VA */
  UINT64 eprocessVa = 0;
  for (UINT32 i = 0; i < Vcpu->Cr3CacheCount; i++) {
    if (Vcpu->Cr3Cache[i].Pid == Pid) {
      eprocessVa = Vcpu->Cr3Cache[i].EprocessVa;
      break;
    }
  }
  if (eprocessVa == 0)
    return STATUS_NOT_FOUND;

  UINT64 guestCr3 = Vcpu->GuestVmcb->StateSave.Cr3;
  UINT64 hostCr3 = __readcr3();

  /* Read PEB pointer from EPROCESS using dynamically discovered offset.
   * Using a hardcoded offset (e.g. 0x550) would break across Windows builds
   * and caused wrong-address reads on this machine (discovered offset
   * is 0x520 — 0x30 bytes earlier than the old hardcode). */
  UINT64 pebVa = ReadKernelVa64(guestCr3, hostCr3,
                                 eprocessVa + g_HvData.Offsets.EprocessPeb);
  if (pebVa == 0)
    return STATUS_NOT_FOUND;

  /* Read PEB.Ldr (PEB + 0x18) — must read under TARGET CR3 (user memory) */
  __writecr3(targetCr3);
  UINT64 ldrVa = *(volatile UINT64 *)(pebVa + 0x18);
  __writecr3(hostCr3);

  if (ldrVa == 0)
    return STATUS_NOT_FOUND;

  /* Read InMemoryOrderModuleList head (PEB_LDR_DATA + 0x20) */
  __writecr3(targetCr3);
  UINT64 listHead = ldrVa + 0x20;
  UINT64 firstFlink = *(volatile UINT64 *)listHead;
  __writecr3(hostCr3);

  if (firstFlink == 0 || firstFlink == listHead)
    return STATUS_NOT_FOUND;

  /* Walk the doubly linked list */
  UINT64 current = firstFlink;
  UINT32 maxIter = 256;
  UINT32 dbgIdx = 0;
  UINT32 dbgMax = DebugBuf ? (DebugBufSize / sizeof(MODULE_DEBUG_ENTRY)) : 0;

  /* Write the search hash as entry[0] so loader can verify */
  if (DebugBuf && dbgMax > 0) {
    __writecr3(SharedPageCr3);
    MODULE_DEBUG_ENTRY *e0 = (MODULE_DEBUG_ENTRY *)DebugBuf;
    e0->hash = ModuleNameHash;
    e0->base = 0xDEAD; /* sentinel to distinguish from module entries */
    __writecr3(hostCr3);
    dbgIdx = 1;
  }

  while (current != listHead && --maxIter > 0) {
    /* LDR_DATA_TABLE_ENTRY:
     * InMemoryOrderLinks is at offset 0x00 (relative to this link)
     * DllBase = link - 0x10 + 0x30 = link + 0x20
     * BaseDllName.Length = link - 0x10 + 0x58 = link + 0x48
     * BaseDllName.Buffer = link - 0x10 + 0x60 = link + 0x50
     *
     * Actually: InMemoryOrderLinks is the SECOND LIST_ENTRY in
     * LDR_DATA_TABLE_ENTRY (first is InLoadOrderLinks at 0x00).
     * So the entry base = current - 0x10 (offsetof InMemoryOrderLinks).
     * DllBase = entry + 0x30 = current + 0x20
     * BaseDllName = entry + 0x58 = current + 0x48 (Length, MaxLength)
     * BaseDllName.Buffer = entry + 0x60 = current + 0x50
     */

    __writecr3(targetCr3);
    UINT64 dllBase = *(volatile UINT64 *)(current + 0x20);
    UINT16 nameLen = *(volatile UINT16 *)(current + 0x48);
    UINT64 nameBuf = *(volatile UINT64 *)(current + 0x50);
    UINT64 nextFlink = *(volatile UINT64 *)current;
    __writecr3(hostCr3);

    if (nameBuf != 0 && nameLen > 0) {
      UINT64 hash = Djb2HashWide(targetCr3, hostCr3, nameBuf, nameLen);

      /* Write debug entry under SharedPageCr3 */
      if (DebugBuf && dbgIdx < dbgMax) {
        __writecr3(SharedPageCr3);
        MODULE_DEBUG_ENTRY *e = (MODULE_DEBUG_ENTRY *)DebugBuf + dbgIdx;
        e->hash = hash;
        e->base = dllBase;
        __writecr3(hostCr3);
        dbgIdx++;
      }

      if (hash == ModuleNameHash) {
        /* Write total count of modules walked so far into last 8 bytes */
        if (DebugBuf && DebugBufSize >= 8) {
          __writecr3(SharedPageCr3);
          *(UINT64 *)(DebugBuf + DebugBufSize - 8) = (UINT64)dbgIdx;
          __writecr3(hostCr3);
        }
        *BaseOut = dllBase;
        return STATUS_SUCCESS;
      }
    }

    current = nextFlink;
  }

  /* Write total count of modules walked into last 8 bytes of debug buf */
  if (DebugBuf && DebugBufSize >= 8) {
    __writecr3(SharedPageCr3);
    *(UINT64 *)(DebugBuf + DebugBufSize - 8) = (UINT64)dbgIdx;
    __writecr3(hostCr3);
  }

  return STATUS_NOT_FOUND;
}
