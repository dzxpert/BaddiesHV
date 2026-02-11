/*
 * svm.h — AMD SVM (Secure Virtual Machine) hardware structure definitions.
 *
 * Every struct in this file is laid out to match the AMD64 Architecture
 * Programmer's Manual Volume 2, Appendix B (VMCB Layout).  The VMCB is
 * a 4KB page-aligned block split into:
 *
 *   [0x000 .. 0x3FF]  Control Area   — intercepts, ASID, NPT, event injection
 *   [0x400 .. 0xFFF]  State Save     — guest register / segment state
 *
 * Offsets are verified against the Linux kernel's arch/x86/include/asm/svm.h.
 * Any change here must be double-checked against both references.
 *
 * These structures are consumed by svm.c (VMCB init, VMEXIT handling) and
 * svm_asm.asm (GUEST_CONTEXT save/restore around VMRUN).
 */

#ifndef SVM_H
#define SVM_H

#include "../shared/hvcomm.h"
#include "npt.h"
#include <intrin.h>
#include <ntddk.h>

/* ============================================================================
 *  Undocumented but exported kernel APIs — manual declarations
 *
 *  KeGenericCallDpc, KeSignalCallDpcSynchronize, and KeSignalCallDpcDone
 *  are exported by ntoskrnl.exe but removed from public WDK headers.
 *  Every open-source hypervisor (SimpleSvm, HyperPlatform) declares these
 *  manually. The signatures have been stable since Vista.
 * ============================================================================
 */

NTKERNELAPI
VOID KeGenericCallDpc(_In_ PKDEFERRED_ROUTINE Routine, _In_opt_ PVOID Context);

NTKERNELAPI
VOID KeSignalCallDpcDone(_In_ PVOID SystemArgument1);

NTKERNELAPI
LOGICAL
KeSignalCallDpcSynchronize(_In_ PVOID SystemArgument2);

/* ============================================================================
 *  MSR Definitions — AMD SVM
 * ============================================================================
 */

#define MSR_EFER 0xC0000080
#define MSR_VM_CR 0xC0010114
#define MSR_VM_HSAVE_PA 0xC0010117
#define MSR_SVM_KEY 0xC0010118
#define MSR_STAR 0xC0000081
#define MSR_LSTAR 0xC0000082
#define MSR_CSTAR 0xC0000083
#define MSR_SFMASK 0xC0000084
#define MSR_KERNEL_GS_BASE 0xC0000102
#define MSR_IA32_SYSENTER_CS 0x00000174
#define MSR_IA32_SYSENTER_ESP 0x00000175
#define MSR_IA32_SYSENTER_EIP 0x00000176
#define MSR_IA32_PAT 0x00000277
#define MSR_IA32_DEBUGCTL 0x000001D9

/* EFER bit definitions */
#define EFER_SVME (1ULL << 12) /* SVM Enable */
#define EFER_LME (1ULL << 8)   /* Long Mode Enable */
#define EFER_LMA (1ULL << 10)  /* Long Mode Active */
#define EFER_NXE (1ULL << 11)  /* No-Execute Enable */
#define EFER_SCE (1ULL << 0)   /* SYSCALL/SYSRET Enable */

/* VM_CR bit definitions */
#define VM_CR_DPD (1ULL << 0)      /* Debug Port Disable */
#define VM_CR_R_INIT (1ULL << 1)   /* Intercept INIT */
#define VM_CR_DIS_A20M (1ULL << 2) /* Disable A20 Masking */
#define VM_CR_SVMDIS (1ULL << 4)   /* SVM Disable */

/* ============================================================================
 *  CPUID Constants
 * ============================================================================
 */

#define CPUID_FN_SVM_FEATURES 0x8000000A
#define CPUID_FN_EXT_FEATURES 0x80000001

/* Fn8000_0001 ECX bit 2 = SVM available */
#define CPUID_SVM_AVAILABLE (1 << 2)

/* Fn8000_000A EDX bits */
#define CPUID_SVM_NPT (1 << 0)              /* Nested Page Tables */
#define CPUID_SVM_NRIP_SAVE (1 << 3)        /* nRIP save on VMEXIT */
#define CPUID_SVM_FLUSH_BY_ASID (1 << 6)    /* TLB flush by ASID */
#define CPUID_SVM_DECODE_ASSIST (1 << 7)    /* Decode assists */
#define CPUID_SVM_CPUID_FILTERING (1 << 12) /* CPUID filter bitmap */

/* ============================================================================
 *  VMEXIT Codes — from AMD APM Vol 2, Appendix C
 * ============================================================================
 */

#define VMEXIT_CR0_READ 0x0000
#define VMEXIT_CR3_READ 0x0003
#define VMEXIT_CR4_READ 0x0004
#define VMEXIT_CR8_READ 0x0008
#define VMEXIT_CR0_WRITE 0x0010
#define VMEXIT_CR3_WRITE 0x0013
#define VMEXIT_CR4_WRITE 0x0014
#define VMEXIT_CR8_WRITE 0x0018
#define VMEXIT_DR0_READ 0x0020
#define VMEXIT_DR7_READ 0x0027
#define VMEXIT_DR0_WRITE 0x0030
#define VMEXIT_DR7_WRITE 0x0037

#define VMEXIT_EXCEPTION_DE 0x0040  /* #DE Divide Error */
#define VMEXIT_EXCEPTION_DB 0x0041  /* #DB Debug */
#define VMEXIT_EXCEPTION_NMI 0x0042 /* NMI */
#define VMEXIT_EXCEPTION_BP 0x0043  /* #BP Breakpoint */
#define VMEXIT_EXCEPTION_OF 0x0044  /* #OF Overflow */
#define VMEXIT_EXCEPTION_BR 0x0045  /* #BR Bound Range */
#define VMEXIT_EXCEPTION_UD 0x0046  /* #UD Invalid Opcode */
#define VMEXIT_EXCEPTION_NM 0x0047  /* #NM Device Not Available */
#define VMEXIT_EXCEPTION_DF 0x0048  /* #DF Double Fault */
#define VMEXIT_EXCEPTION_TS 0x004A  /* #TS Invalid TSS */
#define VMEXIT_EXCEPTION_NP 0x004B  /* #NP Segment Not Present */
#define VMEXIT_EXCEPTION_SS 0x004C  /* #SS Stack-Segment Fault */
#define VMEXIT_EXCEPTION_GP 0x004D  /* #GP General Protection */
#define VMEXIT_EXCEPTION_PF 0x004E  /* #PF Page Fault */
#define VMEXIT_EXCEPTION_MF 0x0050  /* #MF x87 FPU Error */
#define VMEXIT_EXCEPTION_AC 0x0051  /* #AC Alignment Check */
#define VMEXIT_EXCEPTION_MC 0x0052  /* #MC Machine Check */
#define VMEXIT_EXCEPTION_XF 0x0053  /* #XF SIMD Exception */

#define VMEXIT_INTR 0x0060 /* Physical interrupt */
#define VMEXIT_NMI 0x0061
#define VMEXIT_SMI 0x0062
#define VMEXIT_INIT 0x0063
#define VMEXIT_VINTR 0x0064
#define VMEXIT_CR0_SEL_WRITE 0x0065 /* CR0 selective write */
#define VMEXIT_IDTR_READ 0x0066
#define VMEXIT_GDTR_READ 0x0067
#define VMEXIT_LDTR_READ 0x0068
#define VMEXIT_TR_READ 0x0069
#define VMEXIT_IDTR_WRITE 0x006A
#define VMEXIT_GDTR_WRITE 0x006B
#define VMEXIT_LDTR_WRITE 0x006C
#define VMEXIT_TR_WRITE 0x006D
#define VMEXIT_RDTSC 0x006E
#define VMEXIT_RDPMC 0x006F
#define VMEXIT_PUSHF 0x0070
#define VMEXIT_POPF 0x0071
#define VMEXIT_CPUID 0x0072
#define VMEXIT_RSM 0x0073
#define VMEXIT_IRET 0x0074
#define VMEXIT_SWINT 0x0075 /* Software INT */
#define VMEXIT_INVD 0x0076
#define VMEXIT_PAUSE 0x0077
#define VMEXIT_HLT 0x0078
#define VMEXIT_INVLPG 0x0079
#define VMEXIT_INVLPGA 0x007A
#define VMEXIT_IOIO 0x007B
#define VMEXIT_MSR 0x007C
#define VMEXIT_TASK_SWITCH 0x007D
#define VMEXIT_FERR_FREEZE 0x007E
#define VMEXIT_SHUTDOWN 0x007F
#define VMEXIT_VMRUN 0x0080
#define VMEXIT_VMMCALL 0x0081
#define VMEXIT_VMLOAD 0x0082
#define VMEXIT_VMSAVE 0x0083
#define VMEXIT_STGI 0x0084
#define VMEXIT_CLGI 0x0085
#define VMEXIT_SKINIT 0x0086
#define VMEXIT_RDTSCP 0x0087
#define VMEXIT_ICEBP 0x0088
#define VMEXIT_WBINVD 0x0089
#define VMEXIT_MONITOR 0x008A
#define VMEXIT_MWAIT 0x008B
#define VMEXIT_MWAIT_COND 0x008C
#define VMEXIT_XSETBV 0x008D
#define VMEXIT_RDPRU 0x008E
#define VMEXIT_EFER_WRITE_TRAP 0x008F
#define VMEXIT_INVLPGB 0x00A0
#define VMEXIT_INVPCID 0x00A2
#define VMEXIT_MCOMMIT 0x00A3
#define VMEXIT_TLBSYNC 0x00A4
#define VMEXIT_NPF 0x0400 /* Nested Page Fault */
#define VMEXIT_AVIC_INCOMPLETE 0x0401
#define VMEXIT_AVIC_NOACCEL 0x0402
#define VMEXIT_VMGEXIT 0x0403
#define VMEXIT_INVALID ((UINT64) - 1)

/* ============================================================================
 *  VMCB Control Area Intercept Bit Indices
 *
 *  The control area has 6 × 32-bit intercept DWORDs at offset 0x000-0x017.
 *  We define bit positions within each DWORD.
 * ============================================================================
 */

/* DWORD 3 (offset 0x00C) — miscellaneous intercepts */
#define INTERCEPT_INTR (1UL << 0)
#define INTERCEPT_NMI (1UL << 1)
#define INTERCEPT_SMI (1UL << 2)
#define INTERCEPT_INIT (1UL << 3)
#define INTERCEPT_VINTR (1UL << 4)
#define INTERCEPT_CR0_SEL (1UL << 5) /* Selective CR0 write */
#define INTERCEPT_IDTR_RD (1UL << 6)
#define INTERCEPT_GDTR_RD (1UL << 7)
#define INTERCEPT_LDTR_RD (1UL << 8)
#define INTERCEPT_TR_RD (1UL << 9)
#define INTERCEPT_IDTR_WR (1UL << 10)
#define INTERCEPT_GDTR_WR (1UL << 11)
#define INTERCEPT_LDTR_WR (1UL << 12)
#define INTERCEPT_TR_WR (1UL << 13)
#define INTERCEPT_RDTSC_ (1UL << 14) /* Trailing _ to not shadow VMEXIT_ */
#define INTERCEPT_RDPMC_ (1UL << 15)
#define INTERCEPT_PUSHF_ (1UL << 16)
#define INTERCEPT_POPF_ (1UL << 17)
#define INTERCEPT_CPUID_ (1UL << 18)
#define INTERCEPT_RSM_ (1UL << 19)
#define INTERCEPT_IRET_ (1UL << 20)
#define INTERCEPT_INTn (1UL << 21)
#define INTERCEPT_INVD_ (1UL << 22)
#define INTERCEPT_PAUSE_ (1UL << 23)
#define INTERCEPT_HLT_ (1UL << 24)
#define INTERCEPT_INVLPG_ (1UL << 25)
#define INTERCEPT_INVLPGA_ (1UL << 26)
#define INTERCEPT_IOIO_PROT (1UL << 27)
#define INTERCEPT_MSR_PROT (1UL << 28)
#define INTERCEPT_TASK_SW (1UL << 29)
#define INTERCEPT_FERR_FREEZE (1UL << 30)
#define INTERCEPT_SHUTDOWN_ (1UL << 31)

/* DWORD 4 (offset 0x010) — virtualization intercepts */
#define INTERCEPT_VMRUN_ (1UL << 0)
#define INTERCEPT_VMMCALL_ (1UL << 1)
#define INTERCEPT_VMLOAD_ (1UL << 2)
#define INTERCEPT_VMSAVE_ (1UL << 3)
#define INTERCEPT_STGI_ (1UL << 4)
#define INTERCEPT_CLGI_ (1UL << 5)
#define INTERCEPT_SKINIT_ (1UL << 6)
#define INTERCEPT_RDTSCP_ (1UL << 7)
#define INTERCEPT_ICEBP_ (1UL << 8)
#define INTERCEPT_WBINVD_ (1UL << 9)
#define INTERCEPT_MONITOR_ (1UL << 10)
#define INTERCEPT_MWAIT_ (1UL << 11)
#define INTERCEPT_MWAIT_COND_ (1UL << 12)
#define INTERCEPT_XSETBV_ (1UL << 13)
#define INTERCEPT_RDPRU_ (1UL << 14)
#define INTERCEPT_EFER_WRITE_TRAP_ (1UL << 15)

/* DWORD 2 (offset 0x008) — exception intercepts */
#define INTERCEPT_EXCEPTION_MC (1UL << 18) /* #MC = vector 18 */

/* ============================================================================
 *  VMCB Clean Bits — offset 0x0C0 in the control area
 *
 *  Setting a clean bit tells VMRUN "I didn't modify this field group."
 *  Phase 1/2: ALL zero (reload everything).
 *  Phase 3: Enable one at a time after verification.
 * ============================================================================
 */

#define VMCB_CLEAN_INTERCEPTS (1UL << 0)
#define VMCB_CLEAN_IOPM (1UL << 1)
#define VMCB_CLEAN_ASID (1UL << 2)
#define VMCB_CLEAN_TPR (1UL << 3)
#define VMCB_CLEAN_NP (1UL << 4)
#define VMCB_CLEAN_CRX (1UL << 5)
#define VMCB_CLEAN_DRX (1UL << 6)
#define VMCB_CLEAN_DT (1UL << 7)  /* GDT/IDT */
#define VMCB_CLEAN_SEG (1UL << 8) /* Segment registers */
#define VMCB_CLEAN_CR2 (1UL << 9)
#define VMCB_CLEAN_LBR (1UL << 10)
#define VMCB_CLEAN_AVIC (1UL << 11)

/* ============================================================================
 *  EVENTINJ — offset 0x0A8 in the control area
 *
 *  Used to inject exceptions/interrupts into the guest on next VMRUN.
 * ============================================================================
 */

#define EVENTINJ_VECTOR_MASK 0x000000FF
#define EVENTINJ_TYPE_SHIFT 8
#define EVENTINJ_TYPE_MASK (7ULL << EVENTINJ_TYPE_SHIFT)
#define EVENTINJ_TYPE_INTR                                                     \
  (0ULL << EVENTINJ_TYPE_SHIFT)                         /* External interrupt */
#define EVENTINJ_TYPE_NMI (2ULL << EVENTINJ_TYPE_SHIFT) /* NMI */
#define EVENTINJ_TYPE_EXCEPTION                                                \
  (3ULL << EVENTINJ_TYPE_SHIFT) /* Hardware exception */
#define EVENTINJ_TYPE_SOFT_INTR                                                \
  (4ULL << EVENTINJ_TYPE_SHIFT) /* Software interrupt */
#define EVENTINJ_ERROR_VALID (1ULL << 11)
#define EVENTINJ_VALID (1ULL << 31)

/* Convenience: inject #UD (vector 6) with no error code */
#define EVENTINJ_UD (EVENTINJ_VALID | EVENTINJ_TYPE_EXCEPTION | 6)
/* Convenience: inject NMI (vector 2) */
#define EVENTINJ_NMI_INJECT (EVENTINJ_VALID | EVENTINJ_TYPE_NMI | 2)

/* ============================================================================
 *  TLB Control — byte at offset 0x05C
 * ============================================================================
 */

#define TLB_CONTROL_DO_NOTHING 0x00
#define TLB_CONTROL_FLUSH_ALL 0x01
#define TLB_CONTROL_FLUSH_ASID 0x03
#define TLB_CONTROL_FLUSH_NON_GLOBAL_ASID 0x07

/* ============================================================================
 *  VMCB Segment Descriptor — 16 bytes each
 *
 *  ES, CS, SS, DS, FS, GS use selector + attrib + limit + base.
 *  GDTR, IDTR only use limit + base (selector/attrib are reserved).
 *  LDTR, TR use all four fields.
 * ============================================================================
 */

#pragma pack(push, 1)

typedef struct _VMCB_SEGMENT_DESCRIPTOR {
  UINT16 Selector;
  UINT16 Attrib; /* Access rights (12 bits, upper 4 reserved) */
  UINT32 Limit;
  UINT64 Base;
} VMCB_SEGMENT_DESCRIPTOR, *PVMCB_SEGMENT_DESCRIPTOR;

C_ASSERT(sizeof(VMCB_SEGMENT_DESCRIPTOR) == 16);

/* ============================================================================
 *  VMCB Control Area — offsets 0x000 to 0x3FF
 *
 *  Offsets verified against Linux kernel vmcb_control_area.
 * ============================================================================
 */

typedef struct _VMCB_CONTROL_AREA {
  /* 0x000 */ UINT32 InterceptCr; /* CR read (bits 0-15) / write (bits 16-31) */
  /* 0x004 */ UINT32 InterceptDr; /* DR read (bits 0-15) / write (bits 16-31) */
  /* 0x008 */ UINT32
  InterceptException; /* Exception intercept bitmap (32 vectors) */
  /* 0x00C */ UINT32 InterceptMisc1; /* INTR, NMI, CPUID, MSR, HLT, etc. */
  /* 0x010 */ UINT32 InterceptMisc2; /* VMRUN, VMMCALL, VMLOAD, VMSAVE, etc. */
  /* 0x014 */ UINT32 InterceptMisc3; /* INVLPGB, INVPCID, etc. (Zen 3+) */
  /* 0x018 */ UINT8 Reserved1[0x03C - 0x018]; /* 36 bytes to reach 0x03C */
  /* 0x03C */ UINT16 PauseFilterThresh;
  /* 0x03E */ UINT16 PauseFilterCount;
  /* 0x040 */ UINT64 IopmBasePa;  /* I/O Permission Map physical address */
  /* 0x048 */ UINT64 MsrpmBasePa; /* MSR Permission Map physical address */
  /* 0x050 */ UINT64 TscOffset;   /* Guest TSC offset (anti-detection) */
  /* 0x058 */ UINT32 GuestAsid;   /* Address Space ID (must be ≥ 1) */
  /* 0x05C */ UINT8 TlbControl;   /* TLB flush control on VMRUN */
  /* 0x05D */ UINT8 Reserved2[3];
  /* 0x060 */ UINT32 VIntrControl; /* V_TPR, V_IRQ, V_INTR_PRIO, etc. */
  /* 0x064 */ UINT32 VIntrVector;
  /* 0x068 */ UINT32 InterruptShadow; /* Interrupt shadow state */
  /* 0x06C */ UINT8 Reserved3[4];
  /* 0x070 */ UINT64 ExitCode;      /* VMEXIT reason code */
  /* 0x078 */ UINT64 ExitInfo1;     /* VMEXIT info 1 */
  /* 0x080 */ UINT64 ExitInfo2;     /* VMEXIT info 2 */
  /* 0x088 */ UINT64 ExitIntInfo;   /* Exit interrupt info */
  /* 0x090 */ UINT64 NestedControl; /* Bit 0 = NP_ENABLE (nested paging) */
  /* 0x098 */ UINT64 AvicVapicBar;
  /* 0x0A0 */ UINT64 GhcbGpa;
  /* 0x0A8 */ UINT64 EventInj;  /* Event injection (inject on VMRUN) */
  /* 0x0B0 */ UINT64 NestedCr3; /* NPT root page table physical address */
  /* 0x0B8 */ UINT64 VirtExt;   /* LBR virtualization enable, etc. */
  /* 0x0C0 */ UINT32 CleanBits; /* VMCB_CLEAN_* flags */
  /* 0x0C4 */ UINT32 Reserved5;
  /* 0x0C8 */ UINT64 NextRip;      /* nRIP — next sequential RIP after exit */
  /* 0x0D0 */ UINT8 InsnLen;       /* Instruction length (decode assist) */
  /* 0x0D1 */ UINT8 InsnBytes[15]; /* First 15 bytes of faulting insn */
  /* 0x0E0 */ UINT64 AvicBackingPage;
  /* 0x0E8 */ UINT8 Reserved6[8];
  /* 0x0F0 */ UINT64 AvicLogicalId;
  /* 0x0F8 */ UINT64 AvicPhysicalId;
  /* 0x100 */ UINT8 Reserved7[8];
  /* 0x108 */ UINT64 VmsaPA;                  /* SEV-ES VMSA page (not used) */
  /* 0x110 */ UINT8 Reserved8[0x3E0 - 0x110]; /* Pad to end of control area */
  /* 0x3E0 */ UINT8 SoftwareReserved[32];     /* For hypervisor use */
} VMCB_CONTROL_AREA, *PVMCB_CONTROL_AREA;

C_ASSERT(sizeof(VMCB_CONTROL_AREA) == 0x400);

/* ============================================================================
 *  VMCB State Save Area — offsets 0x400 to 0xFFF (relative to VMCB start)
 *
 *  Offsets below are relative to the START of the state save area (0x400).
 *  Verified against Linux kernel vmcb_save_area.
 * ============================================================================
 */

typedef struct _VMCB_STATE_SAVE_AREA {
  /* 0x000 (abs 0x400) */ VMCB_SEGMENT_DESCRIPTOR Es;
  /* 0x010 (abs 0x410) */ VMCB_SEGMENT_DESCRIPTOR Cs;
  /* 0x020 (abs 0x420) */ VMCB_SEGMENT_DESCRIPTOR Ss;
  /* 0x030 (abs 0x430) */ VMCB_SEGMENT_DESCRIPTOR Ds;
  /* 0x040 (abs 0x440) */ VMCB_SEGMENT_DESCRIPTOR Fs;
  /* 0x050 (abs 0x450) */ VMCB_SEGMENT_DESCRIPTOR Gs;
  /* 0x060 (abs 0x460) */ VMCB_SEGMENT_DESCRIPTOR Gdtr;
  /* 0x070 (abs 0x470) */ VMCB_SEGMENT_DESCRIPTOR Ldtr;
  /* 0x080 (abs 0x480) */ VMCB_SEGMENT_DESCRIPTOR Idtr;
  /* 0x090 (abs 0x490) */ VMCB_SEGMENT_DESCRIPTOR Tr;
  /* 0x0A0 (abs 0x4A0) */ UINT8 Reserved1[0x0CB - 0x0A0]; /* 43 bytes */
  /* 0x0CB (abs 0x4CB) */ UINT8 Cpl;
  /* 0x0CC (abs 0x4CC) */ UINT8 Reserved2[4];
  /* 0x0D0 (abs 0x4D0) */ UINT64 Efer;
  /* 0x0D8 (abs 0x4D8) */ UINT8 Reserved3[0x148 - 0x0D8]; /* 112 bytes */
  /* 0x148 (abs 0x548) */ UINT64 Cr4;
  /* 0x150 (abs 0x550) */ UINT64 Cr3;
  /* 0x158 (abs 0x558) */ UINT64 Cr0;
  /* 0x160 (abs 0x560) */ UINT64 Dr7;
  /* 0x168 (abs 0x568) */ UINT64 Dr6;
  /* 0x170 (abs 0x570) */ UINT64 Rflags;
  /* 0x178 (abs 0x578) */ UINT64 Rip;
  /* 0x180 (abs 0x580) */ UINT8 Reserved4[0x1D8 - 0x180]; /* 88 bytes */
  /* 0x1D8 (abs 0x5D8) */ UINT64 Rsp;
  /* 0x1E0 (abs 0x5E0) */ UINT64 SCet;
  /* 0x1E8 (abs 0x5E8) */ UINT64 Ssp;
  /* 0x1F0 (abs 0x5F0) */ UINT64 IsstAddr;
  /* 0x1F8 (abs 0x5F8) */ UINT64 Rax;
  /* 0x200 (abs 0x600) */ UINT64 Star;
  /* 0x208 (abs 0x608) */ UINT64 Lstar;
  /* 0x210 (abs 0x610) */ UINT64 Cstar;
  /* 0x218 (abs 0x618) */ UINT64 Sfmask;
  /* 0x220 (abs 0x620) */ UINT64 KernelGsBase;
  /* 0x228 (abs 0x628) */ UINT64 SysenterCs;
  /* 0x230 (abs 0x630) */ UINT64 SysenterEsp;
  /* 0x238 (abs 0x638) */ UINT64 SysenterEip;
  /* 0x240 (abs 0x640) */ UINT64 Cr2;
  /* 0x248 (abs 0x648) */ UINT8 Reserved5[0x268 - 0x248]; /* 32 bytes */
  /* 0x268 (abs 0x668) */ UINT64 GPat;
  /* 0x270 (abs 0x670) */ UINT64 DbgCtl;
  /* 0x278 (abs 0x678) */ UINT64 BrFrom;
  /* 0x280 (abs 0x680) */ UINT64 BrTo;
  /* 0x288 (abs 0x688) */ UINT64 LastExcpFrom;
  /* 0x290 (abs 0x690) */ UINT64 LastExcpTo;
  /* 0x298 (abs 0x698) */ UINT8 Reserved6[0x2E0 - 0x298]; /* 72 bytes */
  /* 0x2E0 (abs 0x6E0) */ UINT64 SpecCtrl;                /* Guest SPEC_CTRL */
  /* 0x2E8 (abs 0x6E8) */ UINT8
  Reserved7[0x600 - 0x2E8]; /* Pad to 0xC00 total */
} VMCB_STATE_SAVE_AREA, *PVMCB_STATE_SAVE_AREA;

C_ASSERT(sizeof(VMCB_STATE_SAVE_AREA) == 0x600);

/* ============================================================================
 *  VMCB — The complete 4KB Virtual Machine Control Block
 *
 *  Must be allocated on a 4KB-aligned physical page.
 *  Total size = 0x400 (control) + 0x600 (state) = 0xA00.
 *  Hardware requires the page to be 4KB, so padding is included.
 * ============================================================================
 */

typedef struct _VMCB {
  VMCB_CONTROL_AREA Control;      /* 0x000 .. 0x3FF */
  VMCB_STATE_SAVE_AREA StateSave; /* 0x400 .. 0x9FF */
  UINT8 Padding[0x1000 - sizeof(VMCB_CONTROL_AREA) -
                sizeof(VMCB_STATE_SAVE_AREA)];
} VMCB, *PVMCB;

C_ASSERT(sizeof(VMCB) == 0x1000); /* Must be exactly 4KB */

#pragma pack(pop)

/* ============================================================================
 *  GUEST_CONTEXT — GPRs saved/restored by the ASM stub around VMRUN
 *
 *  The VMCB only saves/restores RAX (and RSP/RIP are special-cased).
 *  All other GPRs (RCX, RDX, RBX, RBP, RSI, RDI, R8-R15) must be
 *  saved/restored in software by the ASM VMRUN loop.
 *
 *  This struct is allocated on the host stack by svm_asm.asm.
 *  The field order determines the assembly push/pop order — DO NOT REORDER.
 * ============================================================================
 */

typedef struct _GUEST_CONTEXT {
  /* Saved by the ASM stub before calling SvmVmexitHandler.
   * RAX is in the VMCB state save area, not here.
   * RSP is in the VMCB state save area, not here.
   * RIP is in the VMCB state save area, not here. */
  UINT64 Rax; /* Shadowed copy for handler convenience — synced from VMCB */
  UINT64 Rcx;
  UINT64 Rdx;
  UINT64 Rbx;
  UINT64 Rbp;
  UINT64 Rsi;
  UINT64 Rdi;
  UINT64 R8;
  UINT64 R9;
  UINT64 R10;
  UINT64 R11;
  UINT64 R12;
  UINT64 R13;
  UINT64 R14;
  UINT64 R15;

  /* VMEXIT handler sets this to control the dispatch loop */
  BOOLEAN ExitVm; /* TRUE = devirtualize this processor */
} GUEST_CONTEXT, *PGUEST_CONTEXT;

/* ============================================================================
 *  DESCRIPTOR_TABLE_REGISTER — for storing/loading GDT/IDT base+limit
 * ============================================================================
 */

#pragma pack(push, 1)
typedef struct _DESCRIPTOR_TABLE_REGISTER {
  UINT16 Limit;
  UINT64 Base;
} DESCRIPTOR_TABLE_REGISTER, *PDESCRIPTOR_TABLE_REGISTER;
C_ASSERT(sizeof(DESCRIPTOR_TABLE_REGISTER) == 10);
#pragma pack(pop)

/* ============================================================================
 *  VCPU_DATA — Per-processor virtualization context
 *
 *  One VCPU_DATA is allocated for each logical processor.
 *  Contains the VMCB, host-side state backup, the host stack, and the
 *  host save area required by VM_HSAVE_PA.
 * ============================================================================
 */

/* Host stack size: 16KB — enough for VMEXIT handler + interrupt nesting */
#define HOST_STACK_SIZE (16 * 1024)

/*
 * HOST_STACK_LAYOUT — placed at the TOP of HostStack[].
 * SvmLaunchVm receives a pointer to this as RSP.
 * The VMRUN loop runs entirely on this private stack, so the guest OS
 * (which shares the original DPC stack) can never corrupt these values.
 *
 * Layout (from RSP upward):
 *   [RSP + 0x00] GuestVmcbPa    — physical addr for vmrun/vmload/vmsave
 *   [RSP + 0x08] HostVmcbPa     — for vmload host
 *   [RSP + 0x10] VcpuData       — PVCPU_DATA for handler
 *   [RSP + 0x18] OriginalRsp    — caller's RSP for guest entry / devirt return
 *   [RSP + 0x20] Padding        — alignment to 16 bytes
 */
typedef struct _HOST_STACK_LAYOUT {
  UINT64 GuestVmcbPa;
  UINT64 HostVmcbPa;
  UINT64 VcpuData;    /* cast to PVCPU_DATA in handler */
  UINT64 OriginalRsp; /* caller's stack for return */
  UINT64 Padding1;    /* alignment padding */
  UINT64 Padding2;    /* sizeof = 48 = 0x30, mod 16 = 0 */
} HOST_STACK_LAYOUT, *PHOST_STACK_LAYOUT;

/* Maximum cached CR3 entries (covering typically active processes) */
#define CR3_CACHE_MAX_ENTRIES 64

typedef struct _CR3_CACHE_ENTRY {
  UINT32 Pid;        /* Process ID (0 = unused slot) */
  UINT64 Cr3;        /* DirectoryTableBase from KPROCESS */
  UINT64 EprocessVa; /* Guest VA of EPROCESS (for revalidation) */
} CR3_CACHE_ENTRY, *PCR3_CACHE_ENTRY;

typedef struct _VCPU_DATA {
  /* === Critical SVM structures (must be page-aligned) === */

  /*
   * Guest VMCB — the primary control block for this processor.
   * MmAllocateContiguousMemory guarantees page alignment for the
   * memory backing this, but the VCPU_DATA struct itself may allocate
   * the VMCB at a different aligned location. We store a pointer.
   */
  PVMCB GuestVmcb;
  PHYSICAL_ADDRESS GuestVmcbPa; /* Physical addr for VMRUN */

  /*
   * Host VMCB — used by VMSAVE to store host's hidden state (FS.base,
   * GS.base, TR, LDTR, STAR, LSTAR, etc.).  Separate from guest VMCB.
   */
  PVMCB HostVmcb;
  PHYSICAL_ADDRESS HostVmcbPa;

  /*
   * Host Save Area — pointed to by MSR VM_HSAVE_PA (0xC0010117).
   * Hardware uses this internally during VMRUN/VMEXIT to save host state.
   * Must be a valid 4KB-aligned physical page. Fatal #GP if not set.
   */
  PVOID HostSaveArea;
  PHYSICAL_ADDRESS HostSaveAreaPa;

  /* === Host stack for VMEXIT handler execution === */
  DECLSPEC_ALIGN(16) UINT8 HostStack[HOST_STACK_SIZE];

  /* === Saved host state — restored on devirtualize === */
  DESCRIPTOR_TABLE_REGISTER HostGdtr;
  DESCRIPTOR_TABLE_REGISTER HostIdtr;
  UINT16 HostTr;
  UINT16 HostLdtr;
  UINT64 HostRsp;
  UINT64 HostRip;
  UINT64 HostEfer;
  UINT64 HostCr0;
  UINT64 HostCr3;
  UINT64 HostCr4;

  /* === Per-CPU anti-detection state === */
  UINT64 VirtualEfer; /* Shadow EFER value returned to guest
                       * (SVME bit cleared for stealth)       */
  UINT64 TscOnVmexit; /* TSC at VMEXIT entry — used to measure handler time */

  /* === CR3 cache — avoids calling PsLookupProcessByProcessId from host === */
  CR3_CACHE_ENTRY Cr3Cache[CR3_CACHE_MAX_ENTRIES];
  UINT32 Cr3CacheCount;

  /* === Shared page registration (set during HV_CMD_REGISTER) === */
  UINT64 SharedPageGpa; /* GPA of the loader's HV_SHARED_PAGE   */
  UINT64 SharedPageVa;  /* Original user VA (valid under guest CR3) */
  UINT64 SharedPageCr3; /* Guest CR3 at registration time */
  BOOLEAN SharedPageRegistered;

  /* === Processor identification === */
  UINT32 ProcessorIndex;
  BOOLEAN Subverted; /* TRUE after successful VMRUN */

} VCPU_DATA, *PVCPU_DATA;

/* Verify VCPU_DATA field offsets match the ASM EQU constants.
 * If these fire, the struct layout doesn't match svm_asm.asm. */
C_ASSERT(FIELD_OFFSET(VCPU_DATA, GuestVmcb) == 0x00);
C_ASSERT(FIELD_OFFSET(VCPU_DATA, GuestVmcbPa) == 0x08);
C_ASSERT(FIELD_OFFSET(VCPU_DATA, HostVmcb) == 0x10);
C_ASSERT(FIELD_OFFSET(VCPU_DATA, HostVmcbPa) == 0x18);

/* ============================================================================
 *  Global HV State
 * ============================================================================
 */

typedef struct _HV_GLOBAL_DATA {
  PVCPU_DATA *VcpuArray; /* Array of per-processor VCPU_DATA pointers */
  UINT32 ProcessorCount;
  PVOID MsrPermissionMap; /* MSRPM — 8KB (2 pages), page-aligned */
  PHYSICAL_ADDRESS MsrPermissionMapPa;

  /* Devirtualize synchronization — flag polling, NOT IPI */
  volatile LONG DevirtualizeFlag;   /* TRUE = all processors should exit */
  volatile LONG DevirtualizedCount; /* Counts processors that have exited */

  /* TLB flush synchronization — flag polling */
  volatile LONG TlbFlushPending;
  volatile UINT64 TlbFlushGpa;
  volatile UINT32 TlbFlushAsid;

  /* NPT (Nested Page Tables) — Phase 2 */
  NPT_CONTEXT NptContext; /* Identity map of physical memory */

  /* Feature support flags from CPUID check */
  BOOLEAN NptSupported;
  BOOLEAN NripSaveSupported;
  BOOLEAN CpuidFilterSupported;
  BOOLEAN FlushByAsidSupported;
  BOOLEAN DecodeAssistSupported;

} HV_GLOBAL_DATA, *PHV_GLOBAL_DATA;

/* Single global instance — defined in svm.c */
extern HV_GLOBAL_DATA g_HvData;

/* ============================================================================
 *  MSRPM (MSR Permission Map) — 8KB (2 pages)
 *
 *  Two bitmaps: one for read, one for write, each covering a range of MSRs.
 *  Each MSR gets 2 bits (read + write). The layout is:
 *
 *    [0x0000 .. 0x07FF]  MSRs 0x00000000 – 0x00001FFF  (2KB)
 *    [0x0800 .. 0x0FFF]  MSRs 0xC0000000 – 0xC0001FFF  (2KB)
 *    [0x1000 .. 0x17FF]  MSRs 0xC0010000 – 0xC0011FFF  (2KB)
 *    [0x1800 .. 0x1FFF]  Reserved (2KB)
 *
 *  Total = 8KB = 2 contiguous 4KB pages.
 * ============================================================================
 */

#define MSRPM_SIZE (8 * 1024) /* 8KB */

/* ============================================================================
 *  Function Declarations — svm.c
 * ============================================================================
 */

NTSTATUS SvmCheckSupport(VOID);
NTSTATUS SvmInitializeVcpu(_In_ ULONG ProcessorIndex,
                           _Out_ PVCPU_DATA *VcpuOut);
VOID SvmFreeVcpu(_In_ PVCPU_DATA Vcpu);
NTSTATUS SvmSubvertAllProcessors(VOID);
VOID SvmDevirtualizeAllProcessors(VOID);
BOOLEAN SvmVmexitHandler(_Inout_ PVCPU_DATA Vcpu,
                         _Inout_ PGUEST_CONTEXT GuestCtx);
NTSTATUS SvmAllocateMsrpm(VOID);

/* ============================================================================
 *  Function Declarations — mem_ops.c
 * ============================================================================
 */

NTSTATUS HvCacheCr3(_In_ PVCPU_DATA Vcpu, _In_ UINT32 Pid,
                    _Out_ PUINT64 Cr3Out);
NTSTATUS
HvReadProcessMemory(_In_ PVCPU_DATA Vcpu, _In_ UINT32 Pid, _In_ UINT64 GuestVa,
                    _Out_writes_bytes_(Size) volatile UINT8 *DataBuffer,
                    _In_ UINT64 Size);
NTSTATUS HvWriteProcessMemory(_In_ PVCPU_DATA Vcpu, _In_ UINT32 Pid,
                              _In_ UINT64 GuestVa,
                              _In_reads_bytes_(Size) volatile UINT8 *DataBuffer,
                              _In_ UINT64 Size);

/* ============================================================================
 *  Function Declarations — svm_asm.asm
 * ============================================================================
 */

/*
 * SvmLaunchVm — The VMRUN loop (defined in svm_asm.asm).
 *
 * Enters a VMRUN loop on the current processor using a DEDICATED HOST STACK.
 * The function switches RSP to HostRsp immediately, so the guest OS
 * (running on the original DPC stack) can never corrupt host state.
 *
 * Returns TWICE:
 *   1. First return: guest entry — DPC continues as virtualized guest
 *   2. Second return: devirtualize — cleanup path
 *
 * Parameter:
 *   RCX = HostRsp — pointer to HOST_STACK_LAYOUT at top of HostStack[]
 */
extern VOID SvmLaunchVm(_In_ UINT64 HostRsp);

#endif /* SVM_H */
