/*
 * svm.c — AMD SVM lifecycle: support check, VCPU init, per-processor
 *         subversion, VMEXIT handler dispatch, and devirtualize.
 *
 * This is the brain of the hypervisor. It:
 *   1. Verifies hardware SVM support (CPUID + MSR)
 *   2. Allocates VMCB + host state per logical processor
 *   3. Subverts each processor into the VMRUN loop
 *   4. Dispatches VMEXITs (CPUID, MSR, NMI, #MC, VMMCALL)
 *   5. Tears down cleanly via flag-polling devirtualize
 *
 * IMPORTANT INVARIANTS:
 *   - CLEAN_BITS = 0 in Phase 1 (reload everything on each VMRUN)
 *   - No guest structures modified (IDT/GDT/SSDT untouched)
 *   - VM_HSAVE_PA must be set per-processor before first VMRUN
 *   - GUEST_CONTEXT.Rax is the authoritative shadow; synced to/from VMCB
 */

#include "svm.h"

/* Logging tag for DbgPrintEx */
#define HV_LOG(fmt, ...)                                                       \
  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[BaddiesHV] " fmt "\n",  \
             ##__VA_ARGS__)

#define HV_LOG_ERROR(fmt, ...)                                                 \
  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,                          \
             "[BaddiesHV][ERROR] " fmt "\n", ##__VA_ARGS__)

/* ============================================================================
 *  Forward declarations for static handlers
 * ============================================================================
 */

static VOID HandleCpuid(_In_ PVCPU_DATA Vcpu, _Inout_ PGUEST_CONTEXT GuestCtx);
static VOID HandleHypercall(_In_ PVCPU_DATA Vcpu,
                            _Inout_ PGUEST_CONTEXT GuestCtx,
                            _In_ UINT32 Command);
static VOID HandleMsr(_In_ PVCPU_DATA Vcpu, _Inout_ PGUEST_CONTEXT GuestCtx);
static VOID HandleNmi(_In_ PVCPU_DATA Vcpu);
static VOID HandleMachineCheck(_In_ PVCPU_DATA Vcpu);
static VOID HandleVmmcall(_In_ PVCPU_DATA Vcpu);
static VOID HandleUnknownExit(_In_ PVCPU_DATA Vcpu,
                              _Inout_ PGUEST_CONTEXT GuestCtx);

/* ASM helpers — MSVC x64 has no __readcs()/__readss() etc. intrinsics */
extern UINT16 AsmReadCs(VOID);
extern UINT16 AsmReadSs(VOID);
extern UINT16 AsmReadDs(VOID);
extern UINT16 AsmReadEs(VOID);

/* ============================================================================
 *  Global state — single instance
 * ============================================================================
 */

HV_GLOBAL_DATA g_HvData = {0};

/* Safety valve: max unknown exits before force-devirtualize a processor */
#define MAX_UNKNOWN_EXITS_THRESHOLD 100

/* ============================================================================
 *  SvmCheckSupport — Verify AMD SVM hardware is present and usable
 *
 *  Checks:
 *    1. CPUID Fn8000_0001 ECX[2] — SVM available
 *    2. MSR VM_CR bit 4 — SVM not locked out by BIOS
 *    3. CPUID Fn8000_000A EDX — NPT, nRIP save, CPUID filtering support
 *
 *  Returns STATUS_SUCCESS if all checks pass.
 * ============================================================================
 */

NTSTATUS SvmCheckSupport(VOID) {
  int cpuInfo[4] = {0}; /* EAX, EBX, ECX, EDX */

  /* Step 1: Check CPUID Fn8000_0001 ECX[2] for SVM support */
  __cpuid(cpuInfo, 0x80000001);
  if (!(cpuInfo[2] & CPUID_SVM_AVAILABLE)) {
    HV_LOG_ERROR("SVM not supported by this CPU (CPUID.8000_0001.ECX[2] = 0)");
    return STATUS_NOT_SUPPORTED;
  }

  HV_LOG("SVM available (CPUID.8000_0001.ECX[2] = 1)");

  /* Step 2: Check VM_CR MSR — is SVM locked out by BIOS? */
  UINT64 vmCr = __readmsr(MSR_VM_CR);
  if (vmCr & VM_CR_SVMDIS) {
    HV_LOG_ERROR("SVM disabled by BIOS (VM_CR.SVMDIS = 1). "
                 "Enable AMD-V/SVM in BIOS settings.");
    return STATUS_NOT_SUPPORTED;
  }

  HV_LOG("SVM not locked (VM_CR.SVMDIS = 0)");

  /* Step 3: Check SVM feature flags from CPUID Fn8000_000A */
  __cpuid(cpuInfo, CPUID_FN_SVM_FEATURES);
  UINT32 svmFeatures = (UINT32)cpuInfo[3]; /* EDX */

  g_HvData.NptSupported = !!(svmFeatures & CPUID_SVM_NPT);
  g_HvData.NripSaveSupported = !!(svmFeatures & CPUID_SVM_NRIP_SAVE);
  g_HvData.CpuidFilterSupported = !!(svmFeatures & CPUID_SVM_CPUID_FILTERING);
  g_HvData.FlushByAsidSupported = !!(svmFeatures & CPUID_SVM_FLUSH_BY_ASID);
  g_HvData.DecodeAssistSupported = !!(svmFeatures & CPUID_SVM_DECODE_ASSIST);

  HV_LOG("SVM Features — NPT:%d  nRIP:%d  CpuidFilter:%d  FlushByASID:%d  "
         "DecodeAssist:%d",
         g_HvData.NptSupported, g_HvData.NripSaveSupported,
         g_HvData.CpuidFilterSupported, g_HvData.FlushByAsidSupported,
         g_HvData.DecodeAssistSupported);

  if (!g_HvData.NptSupported) {
    HV_LOG_ERROR(
        "NPT (Nested Page Tables) not supported — required for Phase 2+");
    /* Not fatal for Phase 1, but log it prominently */
  }

  if (!g_HvData.NripSaveSupported) {
    HV_LOG("WARNING: nRIP save not supported — we will use decode assist or "
           "manual instruction length calculation for RIP advancement");
  }

  return STATUS_SUCCESS;
}

/* ============================================================================
 *  SvmAllocateMsrpm — Allocate and initialize the MSR Permission Map
 *
 *  The MSRPM is 8KB (2 pages). Each MSR gets 2 bits: read + write.
 *  We set bits = 1 for MSRs we want to intercept:
 *    - VM_CR          (0xC0010114) — hide SVM availability
 *    - VM_HSAVE_PA    (0xC0010117) — hide host save area
 *    - SVM_KEY        (0xC0010118) — hide SVM key
 *    - EFER           (0xC0000080) — shadow SVME bit
 *
 *  All other MSR accesses pass through without VMEXIT.
 * ============================================================================
 */

/*
 * Helper: Set the intercept bits for a given MSR in the MSRPM.
 *
 * MSRPM layout:
 *   Range 0x0000_0000 – 0x0000_1FFF → byte offset 0x0000, 2 bits per MSR
 *   Range 0xC000_0000 – 0xC000_1FFF → byte offset 0x0800, 2 bits per MSR
 *   Range 0xC001_0000 – 0xC001_1FFF → byte offset 0x1000, 2 bits per MSR
 *
 * Each MSR occupies 2 consecutive bits: bit 0 = read intercept, bit 1 = write.
 */
static VOID MsrpmSetIntercept(_Inout_ PUINT8 Msrpm, _In_ UINT32 MsrIndex,
                              _In_ BOOLEAN InterceptRead,
                              _In_ BOOLEAN InterceptWrite) {
  UINT32 offset;
  UINT32 msrRelative;

  if (MsrIndex <= 0x1FFF) {
    offset = 0x0000;
    msrRelative = MsrIndex;
  } else if (MsrIndex >= 0xC0000000 && MsrIndex <= 0xC0001FFF) {
    offset = 0x0800;
    msrRelative = MsrIndex - 0xC0000000;
  } else if (MsrIndex >= 0xC0010000 && MsrIndex <= 0xC0011FFF) {
    offset = 0x1000;
    msrRelative = MsrIndex - 0xC0010000;
  } else {
    HV_LOG_ERROR("MSR 0x%08X is outside MSRPM range — cannot intercept",
                 MsrIndex);
    return;
  }

  /*
   * Each MSR has 2 bits. The bit position within the bitmap:
   *   bitPos = msrRelative * 2
   *   byteIndex = bitPos / 8
   *   bitInByte = bitPos % 8
   */
  UINT32 bitPos = msrRelative * 2;
  UINT32 byteIndex = offset + (bitPos / 8);
  UINT32 bitInByte = bitPos % 8;

  if (InterceptRead)
    Msrpm[byteIndex] |= (UINT8)(1 << bitInByte);
  if (InterceptWrite)
    Msrpm[byteIndex] |= (UINT8)(1 << (bitInByte + 1));
}

NTSTATUS SvmAllocateMsrpm(VOID) {
  PHYSICAL_ADDRESS maxAddr;
  maxAddr.QuadPart = MAXULONG64;

  /*
   * MSRPM must be a contiguous 8KB block, page-aligned.
   * MmAllocateContiguousMemory returns page-aligned memory.
   */
  g_HvData.MsrPermissionMap = MmAllocateContiguousMemory(MSRPM_SIZE, maxAddr);
  if (g_HvData.MsrPermissionMap == NULL) {
    HV_LOG_ERROR("Failed to allocate MSRPM (8KB)");
    return STATUS_INSUFFICIENT_RESOURCES;
  }

  /* Zero out — all MSR accesses pass through by default */
  RtlZeroMemory(g_HvData.MsrPermissionMap, MSRPM_SIZE);

  /* Set intercepts for SVM-related MSRs */
  PUINT8 msrpm = (PUINT8)g_HvData.MsrPermissionMap;

  /* EFER (0xC0000080) — intercept both reads and writes to shadow SVME */
  MsrpmSetIntercept(msrpm, (UINT32)MSR_EFER, TRUE, TRUE);

  /* VM_CR (0xC0010114) — intercept reads (hide SVM state) */
  MsrpmSetIntercept(msrpm, (UINT32)MSR_VM_CR, TRUE, FALSE);

  /* VM_HSAVE_PA (0xC0010117) — intercept reads (return 0) */
  MsrpmSetIntercept(msrpm, (UINT32)MSR_VM_HSAVE_PA, TRUE, FALSE);

  /* SVM_KEY (0xC0010118) — intercept reads */
  MsrpmSetIntercept(msrpm, (UINT32)MSR_SVM_KEY, TRUE, FALSE);

  g_HvData.MsrPermissionMapPa = MmGetPhysicalAddress(g_HvData.MsrPermissionMap);

  HV_LOG("MSRPM allocated at VA=%p PA=0x%llX", g_HvData.MsrPermissionMap,
         g_HvData.MsrPermissionMapPa.QuadPart);

  return STATUS_SUCCESS;
}

/* ============================================================================
 *  SvmInitializeVcpu — Set up one VCPU for a single logical processor
 *
 *  Allocates:
 *    - Guest VMCB (4KB, page-aligned)
 *    - Host VMCB  (4KB, page-aligned) — for VMSAVE/VMLOAD
 *    - Host Save Area (4KB, page-aligned) — for VM_HSAVE_PA
 *
 *  Populates the VMCB control area with intercept configuration and the
 *  state save area with the current processor's register state.
 *
 *  IMPORTANT: This must run on the target processor (via DPC) because
 *  it reads processor-local state (__readcr0, __readmsr, __sgdt, etc.).
 * ============================================================================
 */

NTSTATUS SvmInitializeVcpu(_In_ ULONG ProcessorIndex,
                           _Out_ PVCPU_DATA *VcpuOut) {
  NTSTATUS status = STATUS_SUCCESS;
  PVCPU_DATA vcpu = NULL;
  PHYSICAL_ADDRESS maxAddr;
  maxAddr.QuadPart = MAXULONG64;

  *VcpuOut = NULL;

  /* Allocate VCPU_DATA (nonpaged pool — must never be paged out) */
  vcpu = (PVCPU_DATA)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(VCPU_DATA),
                                     'UPCV');
  if (vcpu == NULL) {
    HV_LOG_ERROR("CPU %u: Failed to allocate VCPU_DATA (%llu bytes)",
                 ProcessorIndex, (UINT64)sizeof(VCPU_DATA));
    return STATUS_INSUFFICIENT_RESOURCES;
  }
  RtlZeroMemory(vcpu, sizeof(VCPU_DATA));
  vcpu->ProcessorIndex = ProcessorIndex;

  /* ------------------------------------------------------------------
   * Allocate Guest VMCB — 4KB, page-aligned, contiguous physical
   * ------------------------------------------------------------------ */
  vcpu->GuestVmcb = (PVMCB)MmAllocateContiguousMemory(sizeof(VMCB), maxAddr);
  if (vcpu->GuestVmcb == NULL) {
    HV_LOG_ERROR("CPU %u: Failed to allocate Guest VMCB", ProcessorIndex);
    status = STATUS_INSUFFICIENT_RESOURCES;
    goto Cleanup;
  }
  RtlZeroMemory(vcpu->GuestVmcb, sizeof(VMCB));
  vcpu->GuestVmcbPa = MmGetPhysicalAddress(vcpu->GuestVmcb);

  /* ------------------------------------------------------------------
   * Allocate Host VMCB — for VMSAVE/VMLOAD host state
   * ------------------------------------------------------------------ */
  vcpu->HostVmcb = (PVMCB)MmAllocateContiguousMemory(sizeof(VMCB), maxAddr);
  if (vcpu->HostVmcb == NULL) {
    HV_LOG_ERROR("CPU %u: Failed to allocate Host VMCB", ProcessorIndex);
    status = STATUS_INSUFFICIENT_RESOURCES;
    goto Cleanup;
  }
  RtlZeroMemory(vcpu->HostVmcb, sizeof(VMCB));
  vcpu->HostVmcbPa = MmGetPhysicalAddress(vcpu->HostVmcb);

  /* ------------------------------------------------------------------
   * Allocate Host Save Area — pointed to by VM_HSAVE_PA MSR
   * CRITICAL: If this is 0 when VMRUN executes, the CPU faults with #GP
   * ------------------------------------------------------------------ */
  vcpu->HostSaveArea = MmAllocateContiguousMemory(PAGE_SIZE, maxAddr);
  if (vcpu->HostSaveArea == NULL) {
    HV_LOG_ERROR("CPU %u: Failed to allocate Host Save Area", ProcessorIndex);
    status = STATUS_INSUFFICIENT_RESOURCES;
    goto Cleanup;
  }
  RtlZeroMemory(vcpu->HostSaveArea, PAGE_SIZE);
  vcpu->HostSaveAreaPa = MmGetPhysicalAddress(vcpu->HostSaveArea);

  /* ------------------------------------------------------------------
   * Populate VMCB Control Area
   * ------------------------------------------------------------------ */
  PVMCB_CONTROL_AREA ctrl = &vcpu->GuestVmcb->Control;

  /* Intercept CPUID (bit 18 of DWORD 3 at offset 0x00C) */
  ctrl->InterceptMisc1 |= INTERCEPT_CPUID_;

  /* Intercept MSR via MSRPM (bit 28 of DWORD 3) */
  ctrl->InterceptMisc1 |= INTERCEPT_MSR_PROT;

  /* Intercept NMI (bit 1 of DWORD 3) */
  ctrl->InterceptMisc1 |= INTERCEPT_NMI;

  /* Intercept #MC — Machine Check Exception (vector 18 in DWORD 2) */
  ctrl->InterceptException |= INTERCEPT_EXCEPTION_MC;

  /* Intercept VMRUN, VMMCALL, VMLOAD, VMSAVE (DWORD 4 at offset 0x010) */
  ctrl->InterceptMisc2 |= INTERCEPT_VMRUN_;
  ctrl->InterceptMisc2 |= INTERCEPT_VMMCALL_;
  ctrl->InterceptMisc2 |= INTERCEPT_VMLOAD_;
  ctrl->InterceptMisc2 |= INTERCEPT_VMSAVE_;

  /* Intercept STGI/CLGI for safety (prevent guest from manipulating GIF) */
  ctrl->InterceptMisc2 |= INTERCEPT_STGI_;
  ctrl->InterceptMisc2 |= INTERCEPT_CLGI_;

  /* Intercept SHUTDOWN — catches triple faults as VMEXIT instead of
   * crashing to VMware's "CPU shutdown" dialog. Critical for debugging. */
  ctrl->InterceptMisc1 |= INTERCEPT_SHUTDOWN_;

  /* MSRPM base physical address */
  ctrl->MsrpmBasePa = g_HvData.MsrPermissionMapPa.QuadPart;

  /* Guest ASID — must be ≥ 1 (0 is reserved for host) */
  ctrl->GuestAsid = 1;

  /* TLB Control — MUST flush on first VMRUN.
   * AMD APM Vol 2: "Software must flush the entire TLB (by setting
   * TLB_CONTROL to 01h) when bringing up a VMCB for the first time."
   * Without this, stale host TLB entries cause triple faults. */
  ctrl->TlbControl = TLB_CONTROL_FLUSH_ALL;

  /* TSC offset — 0 for now (Phase 3 anti-detection will tune this) */
  ctrl->TscOffset = 0;

  /* CLEAN_BITS = 0 — force full VMCB reload on every VMRUN.
   * Correctness first; optimize in Phase 3. */
  ctrl->CleanBits = 0;

  /* NPT (Nested Paging) — Phase 2: enable and point to identity map */
  if (g_HvData.NptSupported && g_HvData.NptContext.Pml4Pa != 0) {
    ctrl->NestedControl = 1; /* NP_ENABLE bit 0 */
    ctrl->NestedCr3 = g_HvData.NptContext.Pml4Pa;
  } else {
    ctrl->NestedControl = 0;
  }

  /* ------------------------------------------------------------------
   * Populate VMCB State Save Area with current processor state.
   *
   * After VMRUN, the guest should resume execution exactly where it
   * was before subversion — same registers, same segments, same
   * descriptor tables. Any mismatch causes immediate crashes.
   * ------------------------------------------------------------------ */
  PVMCB_STATE_SAVE_AREA state = &vcpu->GuestVmcb->StateSave;

  /* GDT and IDT — read FIRST, needed for segment descriptor extraction */
  _sgdt(&vcpu->HostGdtr);
  __sidt(&vcpu->HostIdtr);

  state->Gdtr.Limit = vcpu->HostGdtr.Limit;
  state->Gdtr.Base = vcpu->HostGdtr.Base;
  state->Idtr.Limit = vcpu->HostIdtr.Limit;
  state->Idtr.Base = vcpu->HostIdtr.Base;

  /* ------------------------------------------------------------------
   * Segment Registers — CS, DS, ES, SS  (VMSAVE does NOT save these!)
   *
   * We read each selector, then extract the segment descriptor from
   * the GDT to get Base, Limit, and Attrib (access rights).
   *
   * VMCB Attrib format (12 bits):
   *   Bits [7:0] = GDT access byte (P, DPL, S, Type)
   *   Bits [11:8] = GDT flags nibble (G, D/B, L, AVL)
   * ------------------------------------------------------------------ */
  {
    PUINT8 gdt = (PUINT8)vcpu->HostGdtr.Base;
    UINT16 sel;
    UINT16 idx;
    PUINT8 entry;
    UINT8 accessByte;
    UINT8 flagsNibble;
    UINT32 limitLow;
    UINT64 baseLow;

    /* --- CS --- */
    sel = AsmReadCs();
    idx = sel >> 3;
    entry = gdt + (idx * 8);
    accessByte = entry[5];
    flagsNibble = (entry[6] >> 4) & 0x0F;
    limitLow = (UINT32)entry[0] | ((UINT32)entry[1] << 8) |
               ((UINT32)(entry[6] & 0x0F) << 16);
    baseLow =
        (UINT64)entry[2] | ((UINT64)entry[3] << 8) | ((UINT64)entry[7] << 24);
    state->Cs.Selector = sel;
    state->Cs.Attrib = (UINT16)((flagsNibble << 8) | accessByte);
    state->Cs.Limit =
        (flagsNibble & 0x08) ? (limitLow << 12) | 0xFFF : limitLow;
    state->Cs.Base = baseLow;

    /* --- SS --- */
    sel = AsmReadSs();
    idx = sel >> 3;
    entry = gdt + (idx * 8);
    accessByte = entry[5];
    flagsNibble = (entry[6] >> 4) & 0x0F;
    limitLow = (UINT32)entry[0] | ((UINT32)entry[1] << 8) |
               ((UINT32)(entry[6] & 0x0F) << 16);
    baseLow =
        (UINT64)entry[2] | ((UINT64)entry[3] << 8) | ((UINT64)entry[7] << 24);
    state->Ss.Selector = sel;
    state->Ss.Attrib = (UINT16)((flagsNibble << 8) | accessByte);
    state->Ss.Limit =
        (flagsNibble & 0x08) ? (limitLow << 12) | 0xFFF : limitLow;
    state->Ss.Base = baseLow;

    /* --- DS --- */
    sel = AsmReadDs();
    if ((sel >> 3) != 0) {
      idx = sel >> 3;
      entry = gdt + (idx * 8);
      accessByte = entry[5];
      flagsNibble = (entry[6] >> 4) & 0x0F;
      limitLow = (UINT32)entry[0] | ((UINT32)entry[1] << 8) |
                 ((UINT32)(entry[6] & 0x0F) << 16);
      baseLow =
          (UINT64)entry[2] | ((UINT64)entry[3] << 8) | ((UINT64)entry[7] << 24);
      state->Ds.Selector = sel;
      state->Ds.Attrib = (UINT16)((flagsNibble << 8) | accessByte);
      state->Ds.Limit =
          (flagsNibble & 0x08) ? (limitLow << 12) | 0xFFF : limitLow;
      state->Ds.Base = baseLow;
    } else {
      /* Null selector — valid in 64-bit mode */
      state->Ds.Selector = sel;
      state->Ds.Attrib = 0;
      state->Ds.Limit = 0;
      state->Ds.Base = 0;
    }

    /* --- ES --- */
    sel = AsmReadEs();
    if ((sel >> 3) != 0) {
      idx = sel >> 3;
      entry = gdt + (idx * 8);
      accessByte = entry[5];
      flagsNibble = (entry[6] >> 4) & 0x0F;
      limitLow = (UINT32)entry[0] | ((UINT32)entry[1] << 8) |
                 ((UINT32)(entry[6] & 0x0F) << 16);
      baseLow =
          (UINT64)entry[2] | ((UINT64)entry[3] << 8) | ((UINT64)entry[7] << 24);
      state->Es.Selector = sel;
      state->Es.Attrib = (UINT16)((flagsNibble << 8) | accessByte);
      state->Es.Limit =
          (flagsNibble & 0x08) ? (limitLow << 12) | 0xFFF : limitLow;
      state->Es.Base = baseLow;
    } else {
      state->Es.Selector = sel;
      state->Es.Attrib = 0;
      state->Es.Limit = 0;
      state->Es.Base = 0;
    }
  }

  /* CPL — kernel mode = ring 0 */
  state->Cpl = 0;

  /* RFLAGS — read current (must have interrupts enabled, reserved bit 1 set) */
  state->Rflags = __readeflags();

  /* Control registers */
  state->Cr0 = __readcr0();
  state->Cr3 = __readcr3();
  state->Cr4 = __readcr4();
  state->Cr2 = 0; /* Will be set if needed */

  /* EFER — read the real value. SVME must be set in the VMCB because
   * VMRUN requires EFER.SVME=1 in the guest state. We enable it in the
   * DPC before the first VMRUN, so capture it here and force SVME on. */
  state->Efer = __readmsr(MSR_EFER) | EFER_SVME;
  vcpu->VirtualEfer = state->Efer & ~EFER_SVME; /* Hide SVME from guest */

  /* RIP, RSP — set in the ASM launcher (SvmLaunchVm) */

  /* PAT - Preserve the host's PAT configuration */
  state->GPat = __readmsr(MSR_IA32_PAT);

  /* Debug registers */
  state->Dr6 = __readdr(6);
  state->Dr7 = __readdr(7);

  /* STAR/LSTAR/CSTAR/SFMASK — critical for SYSCALL/SYSRET */
  state->Star = __readmsr(MSR_STAR);
  state->Lstar = __readmsr(MSR_LSTAR);
  state->Cstar = __readmsr(MSR_CSTAR);
  state->Sfmask = __readmsr(MSR_SFMASK);

  /* SYSENTER MSRs */
  state->SysenterCs = __readmsr(MSR_IA32_SYSENTER_CS);
  state->SysenterEsp = __readmsr(MSR_IA32_SYSENTER_ESP);
  state->SysenterEip = __readmsr(MSR_IA32_SYSENTER_EIP);

  /* KernelGsBase — swapped with GS.Base by SWAPGS */
  state->KernelGsBase = __readmsr(MSR_KERNEL_GS_BASE);

  HV_LOG("CPU %u: VCPU initialized — VMCB VA=%p PA=0x%llX  "
         "HostSave PA=0x%llX  EFER=0x%llX  CR3=0x%llX",
         ProcessorIndex, vcpu->GuestVmcb, vcpu->GuestVmcbPa.QuadPart,
         vcpu->HostSaveAreaPa.QuadPart, state->Efer, state->Cr3);

  *VcpuOut = vcpu;
  return STATUS_SUCCESS;

Cleanup:
  SvmFreeVcpu(vcpu);
  return status;
}

/* ============================================================================
 *  SvmFreeVcpu — Release all memory for a single VCPU
 * ============================================================================
 */

VOID SvmFreeVcpu(_In_ PVCPU_DATA Vcpu) {
  if (Vcpu == NULL)
    return;

  if (Vcpu->HostSaveArea != NULL)
    MmFreeContiguousMemory(Vcpu->HostSaveArea);

  if (Vcpu->HostVmcb != NULL)
    MmFreeContiguousMemory(Vcpu->HostVmcb);

  if (Vcpu->GuestVmcb != NULL)
    MmFreeContiguousMemory(Vcpu->GuestVmcb);

  ExFreePoolWithTag(Vcpu, 'UPCV');
}

/* ============================================================================
 *  VMEXIT Handlers — one per exit type
 * ============================================================================
 */

/*
 * HandleCpuid — CPUID exit handler
 *
 * Checks if the guest issued our magic CPUID leaf (hypercall).
 * Otherwise applies stealth filtering (spoofing, vendor hiding).
 */
static VOID HandleCpuid(_In_ PVCPU_DATA Vcpu, _Inout_ PGUEST_CONTEXT GuestCtx) {
  int cpuInfo[4] = {0};
  UINT32 leaf = (UINT32)GuestCtx->Rax;    /* CPUID leaf in EAX */
  UINT32 subleaf = (UINT32)GuestCtx->Rcx; /* CPUID subleaf in ECX */

  /* ----- Check for magic hypercall leaf ----- */
  if (leaf == HV_CPUID_LEAF) {
    HandleHypercall(Vcpu, GuestCtx, subleaf);
    return;
  }

  /* ----- Execute real CPUID (we're in host context) ----- */
  __cpuidex(cpuInfo, (int)leaf, (int)subleaf);

  /* ----- Stealth: hide hypervisor presence ----- */
  if (leaf == 1) {
    /* Clear ECX bit 31 — "Hypervisor present" flag */
    cpuInfo[2] &= ~(1 << 31);
  }

  /* Filter hypervisor vendor leaves (0x40000000 – 0x4FFFFFFF) */
  if (leaf >= 0x40000000 && leaf <= 0x4FFFFFFF) {
    /* Return zeros — pretend no hypervisor exists */
    cpuInfo[0] = 0;
    cpuInfo[1] = 0;
    cpuInfo[2] = 0;
    cpuInfo[3] = 0;
  }

  /* Write results back to guest registers */
  GuestCtx->Rax = (UINT64)(UINT32)cpuInfo[0];
  GuestCtx->Rbx = (UINT64)(UINT32)cpuInfo[1];
  GuestCtx->Rcx = (UINT64)(UINT32)cpuInfo[2];
  GuestCtx->Rdx = (UINT64)(UINT32)cpuInfo[3];
}

/*
 * HandleHypercall — Process a magic CPUID hypercall from usermode
 *
 * The command ID comes from the CPUID subleaf (ECX at time of CPUID).
 * Data is exchanged via the pre-registered shared page.
 */
static VOID HandleHypercall(_In_ PVCPU_DATA Vcpu,
                            _Inout_ PGUEST_CONTEXT GuestCtx,
                            _In_ UINT32 Command) {
  switch (Command) {
  case HV_CMD_PING:
    /* Echo test — return magic in EAX, 1 in EBX */
    GuestCtx->Rax = HV_CPUID_LEAF;
    GuestCtx->Rbx = 1; /* Success indicator */
    GuestCtx->Rcx = Vcpu->ProcessorIndex;
    GuestCtx->Rdx = 0;
    HV_LOG("CPU %u: PING hypercall — acknowledged", Vcpu->ProcessorIndex);
    break;

  case HV_CMD_DEVIRT:
    /* Signal devirtualize — handled at the VMEXIT dispatch level */
    HV_LOG("CPU %u: DEVIRT hypercall — signaling devirtualize",
           Vcpu->ProcessorIndex);
    InterlockedExchange(&g_HvData.DevirtualizeFlag, TRUE);
    GuestCtx->Rax = HV_CPUID_LEAF;
    GuestCtx->Rbx = 1;
    break;

  case HV_CMD_REGISTER:
    /* Shared page registration — Phase 4.
     * For now, just acknowledge. Full implementation requires
     * CR3 walk to resolve the shared page VA → GPA. */
    HV_LOG("CPU %u: REGISTER hypercall — stub (Phase 4)", Vcpu->ProcessorIndex);
    GuestCtx->Rax = HV_CPUID_LEAF;
    GuestCtx->Rbx = 1;
    break;

  case HV_CMD_READ:
  case HV_CMD_WRITE:
  case HV_CMD_GET_CR3:
    /* Phase 2 stubs — return "not implemented" */
    HV_LOG("CPU %u: Command 0x%X — not implemented (Phase 2)",
           Vcpu->ProcessorIndex, Command);
    GuestCtx->Rax = HV_CPUID_LEAF;
    GuestCtx->Rbx = 0; /* Failure */
    break;

  default:
    HV_LOG("CPU %u: Unknown hypercall command 0x%X", Vcpu->ProcessorIndex,
           Command);
    GuestCtx->Rax = HV_CPUID_LEAF;
    GuestCtx->Rbx = 0; /* Failure — unknown command */
    break;
  }
}

/*
 * HandleMsr — MSR read/write exit handler
 *
 * EXITINFO1 = 0 for RDMSR, 1 for WRMSR.
 * Guest ECX = MSR index.
 * For RDMSR: we write the result to guest EDX:EAX.
 * For WRMSR: guest EDX:EAX contains the value to write.
 */
static VOID HandleMsr(_In_ PVCPU_DATA Vcpu, _Inout_ PGUEST_CONTEXT GuestCtx) {
  UINT32 msrIndex = (UINT32)GuestCtx->Rcx;
  BOOLEAN isWrite = (BOOLEAN)(Vcpu->GuestVmcb->Control.ExitInfo1 & 1);
  UINT64 msrValue;

  if (!isWrite) {
    /* ===== RDMSR ===== */
    switch (msrIndex) {
    case MSR_EFER:
      /* Return the shadow EFER (SVME bit cleared) */
      msrValue = Vcpu->VirtualEfer;
      HV_LOG("CPU %u: RDMSR EFER → returning shadow 0x%llX (real has SVME)",
             Vcpu->ProcessorIndex, msrValue);
      break;

    case MSR_VM_CR:
      /* Pretend SVM is available but not active */
      msrValue = 0;
      break;

    case MSR_VM_HSAVE_PA:
      /* Return 0 — hide host save area */
      msrValue = 0;
      break;

    case MSR_SVM_KEY:
      /* Return 0 */
      msrValue = 0;
      break;

    default:
      /* Should not happen if MSRPM is configured correctly.
       * Pass through the real value as safety. */
      msrValue = __readmsr(msrIndex);
      HV_LOG("CPU %u: Unexpected RDMSR 0x%08X → passthrough 0x%llX",
             Vcpu->ProcessorIndex, msrIndex, msrValue);
      break;
    }

    /* Write result: EDX = high 32, EAX = low 32 */
    GuestCtx->Rax = (UINT64)(UINT32)(msrValue & 0xFFFFFFFF);
    GuestCtx->Rdx = (UINT64)(UINT32)(msrValue >> 32);
  } else {
    /* ===== WRMSR ===== */
    msrValue =
        ((UINT64)(UINT32)GuestCtx->Rdx << 32) | ((UINT64)(UINT32)GuestCtx->Rax);

    switch (msrIndex) {
    case MSR_EFER:
      /* Shadow the write: update the virtual EFER, and pass through
       * the real write with SVME always set (we need it enabled). */
      Vcpu->VirtualEfer = msrValue & ~EFER_SVME; /* Client-visible version */

      /* The actual EFER write to hardware must preserve SVME */
      msrValue |= EFER_SVME;
      Vcpu->GuestVmcb->StateSave.Efer = msrValue;
      HV_LOG("CPU %u: WRMSR EFER — shadow=0x%llX, actual=0x%llX",
             Vcpu->ProcessorIndex, Vcpu->VirtualEfer, msrValue);
      break;

    default:
      /* Pass through */
      __writemsr(msrIndex, msrValue);
      HV_LOG("CPU %u: Unexpected WRMSR 0x%08X = 0x%llX → passthrough",
             Vcpu->ProcessorIndex, msrIndex, msrValue);
      break;
    }
  }
}

/*
 * HandleNmi — NMI exit handler
 *
 * Re-inject the NMI into the guest via EVENTINJ so the OS can
 * process it (crash dumps, watchdog timers, etc.).
 */
static VOID HandleNmi(_In_ PVCPU_DATA Vcpu) {
  /* Re-inject NMI into guest on next VMRUN */
  Vcpu->GuestVmcb->Control.EventInj = EVENTINJ_NMI_INJECT;
  /* No logging here — NMIs are frequent and handler runs with GIF=0 */
}

/*
 * HandleMachineCheck — #MC exception handler
 *
 * Machine checks are CRITICAL hardware errors. We must pass them
 * through to the OS immediately. Do NOT swallow them.
 */
static VOID HandleMachineCheck(_In_ PVCPU_DATA Vcpu) {
  /* Re-inject #MC into guest */
  Vcpu->GuestVmcb->Control.EventInj =
      EVENTINJ_VALID | EVENTINJ_TYPE_EXCEPTION | 18; /* Vector 18 = #MC */
  /* No logging — runs with GIF=0, DbgPrintEx would deadlock */
}

/*
 * HandleVmmcall — VMMCALL exit handler (anti-detection)
 *
 * Guest executes VMMCALL to probe for hypervisor presence.
 * On bare metal without SVM, VMMCALL causes #UD. We mimic that
 * behavior by injecting #UD back into the guest.
 */
static VOID HandleVmmcall(_In_ PVCPU_DATA Vcpu) {
  /* Inject #UD (vector 6) — same result as bare metal */
  Vcpu->GuestVmcb->Control.EventInj = EVENTINJ_UD;

  HV_LOG("CPU %u: VMMCALL intercepted — injecting #UD (stealth)",
         Vcpu->ProcessorIndex);

  /*
   * Do NOT advance RIP — the #UD handler in the guest will handle it.
   * When we inject an exception, the CPU re-checks the faulting instruction
   * address, and the guest's IDT #UD handler will catch it. The guest
   * typically uses __try/__except around VMMCALL to test for HV presence.
   */
}

/*
 * HandleUnknownExit — Default handler for unhandled VMEXIT reasons
 *
 * Logs the exit code, advances RIP past the faulting instruction,
 * and counts occurrences. If we exceed a threshold, devirtualizes
 * the processor as a safety valve (prevents infinite VMEXIT storms).
 */
static UINT32 s_UnknownExitCounts[256] = {
    0}; /* Per-processor would be better; quick hack */

static VOID HandleUnknownExit(_In_ PVCPU_DATA Vcpu,
                              _Inout_ PGUEST_CONTEXT GuestCtx) {
  UNREFERENCED_PARAMETER(GuestCtx);

  /* Try to advance RIP past the faulting instruction */
  if (g_HvData.NripSaveSupported && Vcpu->GuestVmcb->Control.NextRip != 0) {
    Vcpu->GuestVmcb->StateSave.Rip = Vcpu->GuestVmcb->Control.NextRip;
  } else if (Vcpu->GuestVmcb->Control.InsnLen != 0) {
    Vcpu->GuestVmcb->StateSave.Rip += Vcpu->GuestVmcb->Control.InsnLen;
  } else {
    Vcpu->GuestVmcb->StateSave.Rip += 3;
  }

  /* Safety valve: count unknown exits and devirtualize if too many */
  UINT32 idx = Vcpu->ProcessorIndex & 0xFF;
  s_UnknownExitCounts[idx]++;
  if (s_UnknownExitCounts[idx] > MAX_UNKNOWN_EXITS_THRESHOLD) {
    InterlockedExchange(&g_HvData.DevirtualizeFlag, TRUE);
  }
}

/* ============================================================================
 *  SvmVmexitHandler — Main VMEXIT dispatcher
 *
 *  Called from svm_asm.asm on every VMEXIT.
 *
 *  Parameters:
 *    Vcpu     — per-processor virtualization context
 *    GuestCtx — guest GPRs saved by the ASM stub
 *
 *  Returns:
 *    FALSE (0) — continue running the guest (VMRUN loop)
 *    TRUE  (1) — devirtualize this processor
 * ============================================================================
 */

BOOLEAN SvmVmexitHandler(_Inout_ PVCPU_DATA Vcpu,
                         _Inout_ PGUEST_CONTEXT GuestCtx) {
  /*
   * MINIMAL HANDLER — ZERO kernel calls (runs with GIF=0 or GIF=1).
   * Only uses intrinsics and direct VMCB writes. No DbgPrintEx,
   * no InterlockedCompareExchange, no spinlocks.
   */

  /* Capture TSC at VMEXIT entry for timing compensation */
  UINT64 tscEntry = __rdtsc();

  /* Check devirtualize flag (volatile read, no Interlocked needed) */
  if (g_HvData.DevirtualizeFlag) {
    /*
     * Advance guest RIP past the current instruction so the guest
     * doesn't re-execute it after devirtualization.
     */
    UINT64 exitCode = Vcpu->GuestVmcb->Control.ExitCode;
    if (exitCode == VMEXIT_CPUID) {
      if (Vcpu->GuestVmcb->Control.NextRip != 0)
        Vcpu->GuestVmcb->StateSave.Rip = Vcpu->GuestVmcb->Control.NextRip;
      else
        Vcpu->GuestVmcb->StateSave.Rip += 2; /* CPUID = 2 bytes */
    }

    /* Mark this VCPU as devirtualized */
    Vcpu->Subverted = FALSE;
    InterlockedIncrement(&g_HvData.DevirtualizedCount);

    /*
     * Assembly will: STGI, VMLOAD (needs SVME=1), disable SVME,
     * restore guest CR3, build IRETQ frame, restore GPRs, IRETQ.
     * DO NOT disable SVME here — VMLOAD needs it.
     */
    return TRUE;
  }

  /* Reset TLB control (prevent flush storm) */
  Vcpu->GuestVmcb->Control.TlbControl = TLB_CONTROL_DO_NOTHING;

  UINT64 exitCode = Vcpu->GuestVmcb->Control.ExitCode;

  switch (exitCode) {

  case VMEXIT_CPUID: {
    int cpuInfo[4] = {0};
    UINT32 leaf = (UINT32)GuestCtx->Rax;
    UINT32 subleaf = (UINT32)GuestCtx->Rcx;

    /* Check magic hypercall leaf */
    if (leaf == HV_CPUID_LEAF) {
      /* Command byte is in ECX[7:0]. For REGISTER_LO/HI, ECX[31:8]
       * carries VA data, so we must mask to get the command. */
      UINT32 cmd = subleaf & 0xFF;
      switch (cmd) {

      case HV_CMD_PING:
        GuestCtx->Rax = HV_CPUID_LEAF;
        GuestCtx->Rbx = 1;
        GuestCtx->Rcx = Vcpu->ProcessorIndex;
        GuestCtx->Rdx = 0;
        break;

      case HV_CMD_REGISTER_LO: {
        /* Two-step registration: Step 1 — cache low 24 bits of VA.
         * ECX[31:8] = VA[23:0]. Store in VMCB SoftwareReserved. */
        UINT32 vaLo24 = subleaf >> 8;
        *(UINT32 *)&Vcpu->GuestVmcb->Control.SoftwareReserved[0] = vaLo24;
        GuestCtx->Rax = HV_STATUS_SUCCESS;
        break;
      }

      case HV_CMD_REGISTER_HI: {
        /* Two-step registration: Step 2 — combine and translate.
         * ECX[31:8] = VA[47:24]. Combine with cached low 24 bits. */
        UINT32 vaHi24 = subleaf >> 8;
        UINT32 vaLo24 =
            *(UINT32 *)&Vcpu->GuestVmcb->Control.SoftwareReserved[0];
        UINT64 sharedPageVa = ((UINT64)vaHi24 << 24) | (UINT64)vaLo24;

        /* Sign-extend if bit 47 is set (kernel VA) */
        if (sharedPageVa & (1ULL << 47))
          sharedPageVa |= 0xFFFF000000000000ULL;

        /* Translate VA → PA.
         *
         * During VMEXIT the host CR3 is active (from VMRUN time, typically
         * SYSTEM context). The loader's user-mode VA isn't mapped there.
         * We temporarily swap to the guest CR3 (= loader's process CR3,
         * saved in VMCB) so MmGetPhysicalAddress can resolve it.
         *
         * Safe because:
         *   - GIF=0: no interrupts, no preemption
         *   - Kernel code + stack are mapped identically in all processes
         *   - We restore host CR3 immediately after
         */
        UINT64 guestCr3 = Vcpu->GuestVmcb->StateSave.Cr3;
        UINT64 hostCr3 = __readcr3();
        __writecr3(guestCr3);

        PHYSICAL_ADDRESS pa = MmGetPhysicalAddress((PVOID)sharedPageVa);

        __writecr3(hostCr3);

        if (pa.QuadPart == 0) {
          GuestCtx->Rax = HV_STATUS_TRANSLATION_FAIL;
          GuestCtx->Rbx = sharedPageVa; /* diagnostic */
          break;
        }

        Vcpu->SharedPageGpa = (UINT64)pa.QuadPart;
        Vcpu->SharedPageVa = sharedPageVa;
        Vcpu->SharedPageCr3 = guestCr3;
        Vcpu->SharedPageRegistered = TRUE;
        GuestCtx->Rax = HV_STATUS_SUCCESS;
        /* Return reconstructed VA for loader verification */
        GuestCtx->Rbx = (UINT64)(UINT32)(sharedPageVa & 0xFFFFFFFF);
        GuestCtx->Rcx = (UINT64)(UINT32)(sharedPageVa >> 32);
        break;
      }

      case HV_CMD_GET_CR3: {
        if (!Vcpu->SharedPageRegistered) {
          GuestCtx->Rax = HV_STATUS_NOT_REGISTERED;
          break;
        }

        /* Test: read shared page via CR3 swap, return guest CR3 as dummy */
        UINT64 hostCr3 = __readcr3();
        volatile HV_SHARED_PAGE *sp =
            (volatile HV_SHARED_PAGE *)Vcpu->SharedPageVa;

        __writecr3(Vcpu->SharedPageCr3);
        UINT64 magic = sp->request.magic;
        UINT32 reqPid = sp->request.pid;
        __writecr3(hostCr3);

        if (magic != HV_MAGIC) {
          GuestCtx->Rax = HV_STATUS_INVALID_MAGIC;
          break;
        }

        /* Walk EPROCESS list to find target CR3 */
        UINT64 cr3;
        NTSTATUS cmdStatus = HvCacheCr3(Vcpu, reqPid, &cr3);
        if (NT_SUCCESS(cmdStatus)) {
          __writecr3(Vcpu->SharedPageCr3);
          sp->request.result = cr3;
          __writecr3(hostCr3);
          GuestCtx->Rax = HV_STATUS_SUCCESS;
        } else {
          GuestCtx->Rax = HV_STATUS_INVALID_PID;
        }
        break;
      }

      case HV_CMD_READ:
      case HV_CMD_WRITE: {
        /* Read command from registered shared page */
        if (!Vcpu->SharedPageRegistered) {
          GuestCtx->Rax = HV_STATUS_NOT_REGISTERED;
          break;
        }

        UINT64 hostCr3 = __readcr3();
        UINT64 spVa = Vcpu->SharedPageVa;
        volatile HV_SHARED_PAGE *sp = (volatile HV_SHARED_PAGE *)spVa;

        /* --- Phase 1: Read request fields under guest CR3 --- */
        __writecr3(Vcpu->SharedPageCr3);

        UINT64 magic = sp->request.magic;
        UINT32 reqCmd = sp->request.command;
        UINT32 reqPid = sp->request.pid;
        UINT64 reqAddr = sp->request.address;
        UINT64 reqSize = sp->request.size;

        __writecr3(hostCr3);

        /* Validate magic */
        if (magic != HV_MAGIC) {
          GuestCtx->Rax = HV_STATUS_INVALID_MAGIC;
          break;
        }

        /* Clamp size to inline data buffer */
        if (reqSize > HV_DATA_SIZE)
          reqSize = HV_DATA_SIZE;

        NTSTATUS cmdStatus;
        if (cmd == HV_CMD_READ) {
          UINT8 localBuf[256];
          UINT64 readSize = reqSize;
          if (readSize > sizeof(localBuf))
            readSize = sizeof(localBuf);

          cmdStatus = HvReadProcessMemory(Vcpu, reqPid, reqAddr,
                                          (volatile UINT8 *)localBuf, readSize);
          if (NT_SUCCESS(cmdStatus)) {
            __writecr3(Vcpu->SharedPageCr3);
            for (UINT64 i = 0; i < readSize; i++)
              sp->data[i] = localBuf[i];
            __writecr3(hostCr3);
          }
          GuestCtx->Rax = NT_SUCCESS(cmdStatus) ? HV_STATUS_SUCCESS
                                                : HV_STATUS_TRANSLATION_FAIL;
        } else { /* HV_CMD_WRITE */
          UINT8 localBuf[256];
          UINT64 writeSize = reqSize;
          if (writeSize > sizeof(localBuf))
            writeSize = sizeof(localBuf);

          __writecr3(Vcpu->SharedPageCr3);
          for (UINT64 i = 0; i < writeSize; i++)
            localBuf[i] = sp->data[i];
          __writecr3(hostCr3);

          cmdStatus = HvWriteProcessMemory(
              Vcpu, reqPid, reqAddr, (volatile UINT8 *)localBuf, writeSize);
          GuestCtx->Rax = NT_SUCCESS(cmdStatus) ? HV_STATUS_SUCCESS
                                                : HV_STATUS_TRANSLATION_FAIL;
        }
        break;
      }

      case HV_CMD_DEVIRT:
        g_HvData.DevirtualizeFlag = TRUE;
        GuestCtx->Rax = HV_STATUS_SUCCESS;
        /* Don't return TRUE here — let the next VMEXIT check handle it */
        break;

      default:
        GuestCtx->Rax = HV_STATUS_INVALID_COMMAND;
        break;
      }
    } else {
      __cpuidex(cpuInfo, (int)leaf, (int)subleaf);
      GuestCtx->Rax = (UINT64)(UINT32)cpuInfo[0];
      GuestCtx->Rbx = (UINT64)(UINT32)cpuInfo[1];
      GuestCtx->Rcx = (UINT64)(UINT32)cpuInfo[2];
      GuestCtx->Rdx = (UINT64)(UINT32)cpuInfo[3];

      // hide hypervisor thx to wary
      if (leaf == 1)
        GuestCtx->Rcx &= ~(1ULL << 31);
      if (leaf >= 0x40000000 && leaf <= 0x4FFFFFFF) {
        GuestCtx->Rax = 0;
        GuestCtx->Rbx = 0;
        GuestCtx->Rcx = 0;
        GuestCtx->Rdx = 0;
      }
    }

    // advance ripping otherwise we get stuck in a CPUID loop
    if (Vcpu->GuestVmcb->Control.NextRip != 0)
      Vcpu->GuestVmcb->StateSave.Rip = Vcpu->GuestVmcb->Control.NextRip;
    else
      Vcpu->GuestVmcb->StateSave.Rip += 2;
    break;
  }

  case VMEXIT_MSR: {
    UINT32 msrNum = (UINT32)GuestCtx->Rcx;
    BOOLEAN isWrite = (BOOLEAN)(Vcpu->GuestVmcb->Control.ExitInfo1 & 1);

    if (!isWrite) {
      /* ===== RDMSR ===== */
      UINT64 val;
      switch (msrNum) {
      case MSR_EFER:
        val = Vcpu->VirtualEfer; /* Shadow: SVME bit cleared */
        break;
      case MSR_VM_CR:
      case MSR_VM_HSAVE_PA:
      case MSR_SVM_KEY:
        val = 0; /* Hide all SVM state from guest/EAC */
        break;
      default:
        val = __readmsr(msrNum); /* Passthrough */
        break;
      }
      GuestCtx->Rax = (UINT64)(UINT32)(val & 0xFFFFFFFF);
      GuestCtx->Rdx = (UINT64)(UINT32)(val >> 32);
    } else {
      /* ===== WRMSR ===== */
      UINT64 val =
          ((UINT64)(UINT32)GuestCtx->Rdx << 32) | (UINT64)(UINT32)GuestCtx->Rax;
      switch (msrNum) {
      case MSR_EFER:
        Vcpu->VirtualEfer = val & ~EFER_SVME;
        Vcpu->GuestVmcb->StateSave.Efer = val | EFER_SVME;
        break;
      default:
        __writemsr(msrNum, val);
        break;
      }
    }

    /* Advance RIP */
    if (Vcpu->GuestVmcb->Control.NextRip != 0)
      Vcpu->GuestVmcb->StateSave.Rip = Vcpu->GuestVmcb->Control.NextRip;
    else
      Vcpu->GuestVmcb->StateSave.Rip += 2;
    break;
  }

  case VMEXIT_NMI:
    Vcpu->GuestVmcb->Control.EventInj = EVENTINJ_NMI_INJECT;
    break;

  case VMEXIT_EXCEPTION_MC:
    Vcpu->GuestVmcb->Control.EventInj =
        EVENTINJ_VALID | EVENTINJ_TYPE_EXCEPTION | 18;
    break;

  case VMEXIT_VMRUN:
  case VMEXIT_VMMCALL:
  case VMEXIT_VMLOAD:
  case VMEXIT_VMSAVE:
  case VMEXIT_STGI:
  case VMEXIT_CLGI:
    /* Inject #UD — guest shouldn't use SVM instructions */
    Vcpu->GuestVmcb->Control.EventInj =
        EVENTINJ_VALID | EVENTINJ_TYPE_EXCEPTION | 6; /* #UD = vector 6 */
    break;

  case VMEXIT_SHUTDOWN:
    /* Triple fault — force devirtualize */
    g_HvData.DevirtualizeFlag = TRUE;
    return TRUE;

  default:
    /* Unknown: try to advance RIP and continue */
    if (Vcpu->GuestVmcb->Control.NextRip != 0)
      Vcpu->GuestVmcb->StateSave.Rip = Vcpu->GuestVmcb->Control.NextRip;
    else if (Vcpu->GuestVmcb->Control.InsnLen != 0)
      Vcpu->GuestVmcb->StateSave.Rip += Vcpu->GuestVmcb->Control.InsnLen;
    else
      Vcpu->GuestVmcb->StateSave.Rip += 3;
    break;
  }

  /*
   * Anti-detection: subtract VMEXIT handler time from guest-visible TSC.
   * Hardware TscOffset is applied automatically on every guest RDTSC/RDTSCP.
   * This accumulates across VMEXITs, keeping the guest's view of time clean.
   */
  UINT64 tscExit = __rdtsc();
  Vcpu->GuestVmcb->Control.TscOffset -= (INT64)(tscExit - tscEntry);

  return FALSE; /* Continue running the guest */
}

/* ============================================================================
 *  Per-Processor Subversion DPC
 *
 *  Called via KeGenericCallDpc — runs on each logical processor.
 *  Performs the actual SVM enablement and enters the VMRUN loop.
 *
 *  This function never returns normally for non-devirtualized processors;
 *  it returns from SvmLaunchVm only when devirtualize is triggered.
 * ============================================================================
 */

static VOID SvmSubvertProcessorDpc(_In_ PKDPC Dpc,
                                   _In_opt_ PVOID DeferredContext,
                                   _In_opt_ PVOID SystemArgument1,
                                   _In_opt_ PVOID SystemArgument2) {
  UNREFERENCED_PARAMETER(Dpc);
  UNREFERENCED_PARAMETER(DeferredContext);

  ULONG cpuIndex = KeGetCurrentProcessorNumberEx(NULL);
  NTSTATUS status;

  HV_LOG("CPU %u: Subvert DPC starting", cpuIndex);

  /* Allocate and initialize VCPU for this processor */
  PVCPU_DATA vcpu = NULL;
  status = SvmInitializeVcpu(cpuIndex, &vcpu);
  if (!NT_SUCCESS(status)) {
    HV_LOG_ERROR("CPU %u: SvmInitializeVcpu failed (0x%08X)", cpuIndex, status);
    goto DpcComplete;
  }

  /* Store in global array */
  g_HvData.VcpuArray[cpuIndex] = vcpu;

  /* ------------------------------------------------------------------
   * Enable EFER.SVME — this enables SVM on this processor
   * ------------------------------------------------------------------ */
  UINT64 efer = __readmsr(MSR_EFER);
  efer |= EFER_SVME;
  __writemsr(MSR_EFER, efer);

  /* ------------------------------------------------------------------
   * Set VM_HSAVE_PA — MANDATORY before first VMRUN. #GP if zero.
   * ------------------------------------------------------------------ */
  __writemsr(MSR_VM_HSAVE_PA, vcpu->HostSaveAreaPa.QuadPart);

  /* ------------------------------------------------------------------
   * Save host state into the Host VMCB via VMSAVE
   *
   * VMSAVE saves: FS, GS, TR, LDTR (hidden bases), KernelGsBase,
   * STAR, LSTAR, CSTAR, SFMASK, SYSENTER_*
   * ------------------------------------------------------------------ */
  __svm_vmsave(vcpu->HostVmcbPa.QuadPart);

  /* ------------------------------------------------------------------
   * Snapshot the VMCB state save area using VMSAVE
   *
   * This captures the hidden segment state (bases, limits, attributes)
   * that we can't read via intrinsics. VMSAVE writes to the VMCB
   * pointed to by RAX.
   * ------------------------------------------------------------------ */
  __svm_vmsave(vcpu->GuestVmcbPa.QuadPart);

  /* ------------------------------------------------------------------
   * Set the guest RIP and RSP to return to right after SvmLaunchVm
   *
   * The guest VMCB's RIP and RSP are set so that when we devirtualize,
   * execution continues right after the VMRUN loop. For now, we set
   * them to the current context because VMRUN will start the guest
   * from wherever these point.
   *
   * Actually, VMRUN reads RIP/RSP from the VMCB to decide where the
   * guest starts. We want the guest to "resume" where it is now —
   * which SvmLaunchVm handles by setting up the context correctly.
   * The guest's first instruction will be the one after the VMRUN
   * in the ASM loop.
   * ------------------------------------------------------------------ */

  /* Mark as subverted BEFORE SvmLaunchVm — the first VMRUN starts the
   * guest at @@GuestEntry which returns from SvmLaunchVm. The DPC
   * callback continues executing as a virtualized guest from here. */
  vcpu->Subverted = TRUE;

  HV_LOG("CPU %u: Entering VMRUN — EFER=0x%llX", cpuIndex, efer);

  /* ------------------------------------------------------------------
   * Set up HOST_STACK_LAYOUT at the top of the dedicated HostStack[].
   * This private stack is inside VCPU_DATA and the guest OS can NEVER
   * corrupt it (the guest runs on the original DPC stack).
   * ------------------------------------------------------------------ */
  {
    UINT8 *stackTop = vcpu->HostStack + HOST_STACK_SIZE;
    PHOST_STACK_LAYOUT layout =
        (PHOST_STACK_LAYOUT)(stackTop - sizeof(HOST_STACK_LAYOUT));
    layout->GuestVmcbPa = vcpu->GuestVmcbPa.QuadPart;
    layout->HostVmcbPa = vcpu->HostVmcbPa.QuadPart;
    layout->VcpuData = (UINT64)vcpu;
    layout->OriginalRsp = 0; /* Filled by ASM prologue */
    layout->Padding1 = 0;
    layout->Padding2 = 0;

    /* First return: guest entry. Second return: devirtualize. */
    SvmLaunchVm((UINT64)layout);
  }

  /* ------------------------------------------------------------------
   * We get here TWICE:
   *   1. First time: DevirtualizeFlag is FALSE. This is the guest
   *      returning after the first VMRUN. Complete the DPC.
   *   2. Second time: DevirtualizeFlag is TRUE. Devirtualize path.
   *      Not in a DPC — do NOT call KeSignalCallDpcDone.
   * ------------------------------------------------------------------ */
  if (InterlockedCompareExchange(&g_HvData.DevirtualizeFlag, TRUE, TRUE) ==
      TRUE) {
    /* --- DEVIRTUALIZE PATH (second return) --- */
    HV_LOG("CPU %u: VMRUN loop exited — devirtualized", cpuIndex);

    /* Disable SVME */
    efer = __readmsr(MSR_EFER);
    efer &= ~EFER_SVME;
    __writemsr(MSR_EFER, efer);

    /* Clear VM_HSAVE_PA */
    __writemsr(MSR_VM_HSAVE_PA, 0);

    vcpu->Subverted = FALSE;
    InterlockedIncrement(&g_HvData.DevirtualizedCount);

    /* NOT in a DPC — do not call KeSignalCallDpc* */
    return;
  }

  /* --- FIRST RETURN (guest entry) --- */
  HV_LOG("CPU %u: Guest entry — now virtualized", cpuIndex);

DpcComplete:
  /* Signal DPC completion to the framework */
  KeSignalCallDpcSynchronize(SystemArgument2);
  KeSignalCallDpcDone(SystemArgument1);
}

/* ============================================================================
 *  SvmSubvertAllProcessors — Launch HV on all logical processors
 *
 *  Uses KeGenericCallDpc to run SvmSubvertProcessorDpc on every core.
 *  Returns when ALL processors have been subverted.
 * ============================================================================
 */

NTSTATUS SvmSubvertAllProcessors(VOID) {
  NTSTATUS status;

  g_HvData.ProcessorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
  HV_LOG("Subverting %u processors...", g_HvData.ProcessorCount);

  /* Allocate array of VCPU_DATA pointers */
  SIZE_T arraySize = g_HvData.ProcessorCount * sizeof(PVCPU_DATA);
  g_HvData.VcpuArray =
      (PVCPU_DATA *)ExAllocatePool2(POOL_FLAG_NON_PAGED, arraySize, 'ARVC');
  if (g_HvData.VcpuArray == NULL) {
    HV_LOG_ERROR("Failed to allocate VCPU array");
    return STATUS_INSUFFICIENT_RESOURCES;
  }
  RtlZeroMemory(g_HvData.VcpuArray, arraySize);

  /* Allocate MSRPM (shared across all processors) */
  status = SvmAllocateMsrpm();
  if (!NT_SUCCESS(status)) {
    ExFreePoolWithTag(g_HvData.VcpuArray, 'ARVC');
    g_HvData.VcpuArray = NULL;
    return status;
  }

  /* Initialize synchronization */
  InterlockedExchange(&g_HvData.DevirtualizeFlag, FALSE);
  InterlockedExchange(&g_HvData.DevirtualizedCount, 0);

  /* Build NPT identity map (Phase 2) */
  if (g_HvData.NptSupported) {
    status = NptBuildIdentityMap(&g_HvData.NptContext);
    if (!NT_SUCCESS(status)) {
      HV_LOG_ERROR("Failed to build NPT identity map: 0x%08X", status);
      ExFreePoolWithTag(g_HvData.VcpuArray, 'ARVC');
      g_HvData.VcpuArray = NULL;
      return status;
    }
    HV_LOG("NPT identity map built.  PML4 PA = 0x%llX",
           g_HvData.NptContext.Pml4Pa);
  }

  /* Launch DPC on all processors */
  KeGenericCallDpc(SvmSubvertProcessorDpc, NULL);

  /* Verify all processors subverted */
  UINT32 subvertedCount = 0;
  for (UINT32 i = 0; i < g_HvData.ProcessorCount; i++) {
    if (g_HvData.VcpuArray[i] != NULL && g_HvData.VcpuArray[i]->Subverted) {
      subvertedCount++;
    }
  }

  HV_LOG("Subversion complete: %u / %u processors active", subvertedCount,
         g_HvData.ProcessorCount);

  if (subvertedCount == 0) {
    HV_LOG_ERROR("No processors subverted — SVM launch failed!");
    return STATUS_UNSUCCESSFUL;
  }

  return STATUS_SUCCESS;
}

/* ============================================================================
 *  SvmDevirtualizeAllProcessors — Tear down HV on all processors
 *
 *  Uses flag polling (not IPIs) to avoid livelock when processors
 *  are in CLGI state.
 *
 *  Flow:
 *    1. Set g_DevirtualizeFlag = TRUE
 *    2. Each processor checks the flag at the top of SvmVmexitHandler
 *    3. When a processor sees it, it exits the VMRUN loop
 *    4. We wait (with timeout) for all processors to confirm exit
 *    5. Free all resources
 * ============================================================================
 */

#define DEVIRTUALIZE_TIMEOUT_MS 5000 /* 5 seconds max wait */

VOID SvmDevirtualizeAllProcessors(VOID) {
  if (g_HvData.VcpuArray == NULL) {
    HV_LOG("No VCPUs to devirtualize");
    return;
  }

  HV_LOG("Devirtualizing all processors...");

  /* Step 1: Signal all processors to exit */
  InterlockedExchange(&g_HvData.DevirtualizeFlag, TRUE);

  /* Step 2: Wait for all processors to exit the VMRUN loop.
   *
   * Each processor increments DevirtualizedCount in SvmSubvertProcessorDpc
   * after exiting the VMRUN loop and disabling SVME.
   *
   * Timeout prevents infinite hang if a processor is stuck. */
  LARGE_INTEGER interval;
  interval.QuadPart = -10000; /* 1ms in 100ns units */

  UINT32 waited = 0;
  UINT32 activeCount = 0;

  /* Count how many were actually subverted */
  for (UINT32 i = 0; i < g_HvData.ProcessorCount; i++) {
    if (g_HvData.VcpuArray[i] != NULL && g_HvData.VcpuArray[i]->Subverted) {
      activeCount++;
    }
  }

  while ((UINT32)g_HvData.DevirtualizedCount < activeCount &&
         waited < DEVIRTUALIZE_TIMEOUT_MS) {
    KeDelayExecutionThread(KernelMode, FALSE, &interval);
    waited++;
  }

  if ((UINT32)g_HvData.DevirtualizedCount < activeCount) {
    HV_LOG_ERROR("Devirtualize TIMEOUT! Only %ld / %u processors responded. "
                 "Issuing bugcheck to prevent silent corruption.",
                 g_HvData.DevirtualizedCount, activeCount);
    KeBugCheckEx(0xBADD1E50, /* Custom bugcheck code */
                 (ULONG_PTR)g_HvData.DevirtualizedCount, (ULONG_PTR)activeCount,
                 0, 0);
  }

  HV_LOG("All %u processors devirtualized successfully", activeCount);

  /* Step 3: Free VCPU resources */
  for (UINT32 i = 0; i < g_HvData.ProcessorCount; i++) {
    if (g_HvData.VcpuArray[i] != NULL) {
      SvmFreeVcpu(g_HvData.VcpuArray[i]);
      g_HvData.VcpuArray[i] = NULL;
    }
  }

  /* Free VCPU array */
  ExFreePoolWithTag(g_HvData.VcpuArray, 'ARVC');
  g_HvData.VcpuArray = NULL;

  /* Free MSRPM */
  if (g_HvData.MsrPermissionMap != NULL) {
    MmFreeContiguousMemory(g_HvData.MsrPermissionMap);
    g_HvData.MsrPermissionMap = NULL;
  }

  /* Free NPT page tables */
  NptDestroyIdentityMap(&g_HvData.NptContext);

  HV_LOG("All resources freed — devirtualize complete");
}
