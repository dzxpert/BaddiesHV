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
 * HvTranslateGuestVa — Translate a guest VA to GPA using CR3 swap.
 *
 * Instead of manually walking 4-level page tables via MmGetVirtualForPhysical
 * (which fails for page table pages during VMEXIT), we temporarily swap to
 * the target CR3 and call MmGetPhysicalAddress directly.
 *
 * Safe because:
 *   - GIF=0: no interrupts, no preemption
 *   - Kernel code + stack are mapped identically in all processes
 *   - We restore the original CR3 immediately after
 * ============================================================================
 */

static NTSTATUS HvTranslateGuestVa(_In_ UINT64 GuestCr3, _In_ UINT64 GuestVa,
                                   _Out_ PUINT64 GuestPa) {

  *GuestPa = 0;

  /* Swap to target CR3 so MmGetPhysicalAddress can resolve the VA */
  UINT64 origCr3 = __readcr3();
  __writecr3(GuestCr3);

  PHYSICAL_ADDRESS pa = MmGetPhysicalAddress((PVOID)GuestVa);

  __writecr3(origCr3);

  if (pa.QuadPart == 0)
    return STATUS_UNSUCCESSFUL;

  *GuestPa = (UINT64)pa.QuadPart;
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

/* Windows 10/11 22H2 EPROCESS offsets */
#define EPROCESS_ACTIVE_PROCESS_LINKS 0x448
#define EPROCESS_UNIQUE_PROCESS_ID 0x440
#define EPROCESS_DIRECTORY_TABLE_BASE 0x028

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
 * ReadKernelVa64 — Read a UINT64 from a kernel VA.
 *
 * Direct read under CR3 swap. Safe because:
 *   - KPCR, KTHREAD, EPROCESS are NonPagedPool — always resident
 *   - Kernel mappings are identical in all CR3s
 *   - Addresses are validated as canonical kernel VAs before access
 *   - GIF=0 prevents preemption
 */
static UINT64 ReadKernelVa64(UINT64 GuestCr3, UINT64 HostCr3, UINT64 KernelVa) {
  /* Reject non-kernel addresses to prevent page faults on garbage pointers */
  if (KernelVa < 0xFFFF800000000000ULL)
    return 0;

  __writecr3(GuestCr3);
  UINT64 value = *(volatile UINT64 *)KernelVa;
  __writecr3(HostCr3);

  return value;
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

  /* KPCR + 0x180 = KPRCB, KPRCB + 0x008 = CurrentThread → offset 0x188 */
  UINT64 currentThreadVa = ReadKernelVa64(guestCr3, hostCr3, kpcrVa + 0x188);
  if (currentThreadVa == 0)
    return STATUS_UNSUCCESSFUL;

  /* KTHREAD + 0x98 = ApcState, ApcState + 0x20 = Process (EPROCESS*) */
  UINT64 currentProcessVa =
      ReadKernelVa64(guestCr3, hostCr3, currentThreadVa + 0x98 + 0x20);
  if (currentProcessVa == 0)
    return STATUS_UNSUCCESSFUL;

  /* Walk ActiveProcessLinks starting from current EPROCESS */
  UINT64 headProcessVa = currentProcessVa;
  UINT64 walkProcessVa = currentProcessVa;
  UINT32 maxIterations = 4096;

  do {
    /* Read UniqueProcessId */
    UINT64 procPid = ReadKernelVa64(guestCr3, hostCr3,
                                    walkProcessVa + EPROCESS_UNIQUE_PROCESS_ID);

    if ((UINT32)procPid == Pid) {
      /* Found it! Read DirectoryTableBase */
      UINT64 cr3 = ReadKernelVa64(
          guestCr3, hostCr3, walkProcessVa + EPROCESS_DIRECTORY_TABLE_BASE);

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

    /* Follow ActiveProcessLinks.Flink */
    UINT64 flink = ReadKernelVa64(
        guestCr3, hostCr3, walkProcessVa + EPROCESS_ACTIVE_PROCESS_LINKS);
    if (flink == 0)
      break;

    /* flink points to the LIST_ENTRY inside the next EPROCESS.
     * Subtract ACTIVE_PROCESS_LINKS offset to get EPROCESS base. */
    walkProcessVa = flink - EPROCESS_ACTIVE_PROCESS_LINKS;

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

  /* Get target process CR3 */
  UINT64 targetCr3;
  NTSTATUS status = HvCacheCr3(Vcpu, Pid, &targetCr3);
  if (!NT_SUCCESS(status))
    return status;

  /* Swap to target CR3 and read directly */
  UINT64 hostCr3 = __readcr3();
  __writecr3(targetCr3);

  for (UINT64 i = 0; i < Size; i++) {
    DataBuffer[i] = *(volatile UINT8 *)(GuestVa + i);
  }

  __writecr3(hostCr3);
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

  /* Get target process CR3 */
  UINT64 targetCr3;
  NTSTATUS status = HvCacheCr3(Vcpu, Pid, &targetCr3);
  if (!NT_SUCCESS(status))
    return status;

  /* Swap to target CR3 and write directly */
  UINT64 hostCr3 = __readcr3();
  __writecr3(targetCr3);

  for (UINT64 i = 0; i < Size; i++) {
    *(volatile UINT8 *)(GuestVa + i) = DataBuffer[i];
  }

  __writecr3(hostCr3);
  return STATUS_SUCCESS;
}
