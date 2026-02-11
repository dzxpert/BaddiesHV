;
; svm_asm.asm — AMD SVM VMRUN loop (dedicated host stack architecture)
;
; Based on SimpleSvm by Satoshi Tanda:
;   - SvmLaunchVm receives a single parameter: HostRsp
;   - Immediately switches to dedicated host stack (mov rsp, rcx)
;   - Guest OS runs on its own stack and CANNOT corrupt host data
;   - GIF=0 throughout handler (SimpleSvm pattern)
;   - XMM0-5 saved/restored around handler call
;   - STGI before handler call (our handlers may need interrupts)
;
; HOST_STACK_LAYOUT at [RSP] (set up by C code):
;   [RSP + 0x00]  GuestVmcbPa
;   [RSP + 0x08]  HostVmcbPa
;   [RSP + 0x10]  VcpuData (PVCPU_DATA)
;   [RSP + 0x18]  OriginalRsp (caller's RSP for return)
;   [RSP + 0x20]  Padding
;
; Below RSP, we allocate space on the HOST STACK for:
;   GUEST_CONTEXT (128 bytes), XMM save (96 bytes), shadow space (32 bytes)
;

; VMCB field offsets
VMCB_RAX        EQU 5F8h
VMCB_RIP        EQU 578h
VMCB_RSP        EQU 5D8h

; VCPU_DATA field offsets
VCPU_VMCB_VA    EQU 0
VCPU_HOST_PA    EQU 18h

; HOST_STACK_LAYOUT offsets (from base RSP = top of host stack data)
HSL_VMCB_PA     EQU 0
HSL_HOST_PA     EQU 8
HSL_VCPU        EQU 10h
HSL_ORIG_RSP    EQU 18h

; Frame below HSL (allocated by sub rsp):
;   [rsp + 0x00 .. 0x1F]   shadow space (32 bytes)
;   [rsp + 0x20 .. 0x7F]   XMM0-5 save area (96 bytes)
;   [rsp + 0x80 .. 0xFF]   GUEST_CONTEXT (128 bytes)
;   Total = 0x100 = 256 bytes
;   We need RSP mod 16 = 0 for movaps.
;   After mov rsp, rcx: RSP = rcx (aligned by C code to mod 16 = 0)
;   sub 0x100: still mod 16 = 0.  CORRECT.
;   But we need shadow+8 for call alignment: CALL pushes ret addr,
;   making RSP mod 16 = 8 at callee entry (x64 ABI requirement).
;   So RSP mod 16 = 0 at our CALL instruction is correct.
;
FRAME_BELOW     EQU 100h    ; 256 bytes below HSL base
XMM_SAVE        EQU 20h     ; XMM save at RSP + 0x20
GUEST_CTX       EQU 80h     ; GUEST_CONTEXT at RSP + 0x80

.CODE

EXTERN SvmVmexitHandler:PROC

; =============================================================================
; SvmLaunchVm — Enter the VMRUN loop on dedicated host stack
;
; Parameter (x64 ABI):
;   RCX = HostRsp — pointer to HOST_STACK_LAYOUT on the dedicated host stack
;
; The function returns TWICE:
;   1. First return: guest entry (DPC continues as virtualized guest)
;   2. Second return: devirtualize
; =============================================================================

SvmLaunchVm PROC

    ; =========================================================================
    ; Save callee-saved registers on CALLER's stack (DPC stack)
    ; These will be restored when the guest "returns" from this function.
    ; =========================================================================
    push    rbp
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15

    ; =========================================================================
    ; Save caller's RSP to the host stack layout (for guest entry / devirt)
    ; =========================================================================
    mov     [rcx + HSL_ORIG_RSP], rsp

    ; =========================================================================
    ; Switch to DEDICATED HOST STACK
    ; From this point, RSP is on a private 16KB stack that the guest
    ; can NEVER corrupt (it's inside VCPU_DATA, not on the DPC stack).
    ; =========================================================================
    mov     rsp, rcx            ; RSP = &HOST_STACK_LAYOUT (top of host data)

    ; =========================================================================
    ; Set up guest VMCB for first VMRUN
    ; =========================================================================
    mov     r13, [rsp + HSL_VCPU]       ; r13 = VCPU_DATA*
    mov     rax, [r13 + VCPU_VMCB_VA]   ; rax = Guest VMCB VA

    ; Guest starts at @@GuestEntry with the caller's (DPC) stack
    lea     rcx, [@@GuestEntry]
    mov     [rax + VMCB_RIP], rcx
    mov     rcx, [rsp + HSL_ORIG_RSP]
    mov     [rax + VMCB_RSP], rcx

    ; Save host hidden state to host VMCB
    mov     rax, [rsp + HSL_HOST_PA]
    vmsave  rax

    ; Allocate frame below HSL for GUEST_CONTEXT, XMM save, shadow space
    sub     rsp, FRAME_BELOW       ; RSP mod 16 = 0 (256 mod 16 = 0)

    ; Zero GUEST_CONTEXT
    lea     rdi, [rsp + GUEST_CTX]
    xor     eax, eax
    mov     ecx, 128 / 8
    rep     stosq

    ; Reload HSL base for loop (HSL is at rsp + FRAME_BELOW)
    ; Define: HSL(x) = rsp + FRAME_BELOW + x
    ; This is because we did sub rsp, FRAME_BELOW after setting rsp = HSL base.

    ; CLGI — disable interrupts
    clgi

    ; =====================================================================
    ;                         VMRUN HOT LOOP
    ; =====================================================================
ALIGN 16
@@Loop:
    ; Reload pointers (r13/r14 may have been clobbered by C handler)
    mov     r13, [rsp + FRAME_BELOW + HSL_VCPU]     ; VCPU_DATA*
    lea     r14, [rsp + GUEST_CTX]                   ; GUEST_CONTEXT*

    ; Sync GuestContext.Rax -> VMCB.StateSave.Rax
    mov     rax, [r13 + VCPU_VMCB_VA]
    mov     rcx, [r14]
    mov     [rax + VMCB_RAX], rcx

    ; VMLOAD guest hidden segments
    mov     rax, [rsp + FRAME_BELOW + HSL_VMCB_PA]
    vmload  rax

    ; Load ALL guest GPRs from GUEST_CONTEXT
    mov     rcx, [r14 + 08h]
    mov     rdx, [r14 + 10h]
    mov     rbx, [r14 + 18h]
    mov     rbp, [r14 + 20h]
    mov     rsi, [r14 + 28h]
    mov     rdi, [r14 + 30h]
    mov     r8,  [r14 + 38h]
    mov     r9,  [r14 + 40h]
    mov     r10, [r14 + 48h]
    mov     r11, [r14 + 50h]
    mov     r12, [r14 + 58h]
    mov     r13, [r14 + 60h]
    mov     r15, [r14 + 70h]
    mov     r14, [r14 + 68h]           ; LAST (destroys our pointer)

    ; --- VMRUN ---
    mov     rax, [rsp + FRAME_BELOW + HSL_VMCB_PA]
    vmrun   rax

    ; =================================================================
    ;  VMEXIT — GIF=0, RSP restored from host save area
    ;  RSP = our post-sub value (host stack). Guest stack is separate.
    ; =================================================================

    ; VMSAVE guest hidden segments
    mov     rax, [rsp + FRAME_BELOW + HSL_VMCB_PA]
    vmsave  rax

    ; Save guest R14/R13 (they're guest values in registers)
    lea     rax, [rsp + GUEST_CTX]
    mov     [rax + 68h], r14
    mov     [rax + 60h], r13
    mov     r14, rax                    ; r14 = GUEST_CONTEXT* again

    ; Save remaining guest GPRs
    mov     [r14 + 08h], rcx
    mov     [r14 + 10h], rdx
    mov     [r14 + 18h], rbx
    mov     [r14 + 20h], rbp
    mov     [r14 + 28h], rsi
    mov     [r14 + 30h], rdi
    mov     [r14 + 38h], r8
    mov     [r14 + 40h], r9
    mov     [r14 + 48h], r10
    mov     [r14 + 50h], r11
    mov     [r14 + 58h], r12
    mov     [r14 + 70h], r15

    ; Save guest RAX from VMCB
    mov     r13, [rsp + FRAME_BELOW + HSL_VCPU]
    mov     rax, [r13 + VCPU_VMCB_VA]
    mov     rax, [rax + VMCB_RAX]
    mov     [r14], rax

    ; VMLOAD host hidden segments
    mov     rax, [rsp + FRAME_BELOW + HSL_HOST_PA]
    vmload  rax

    ; Save guest XMM0-5 (volatile — C handler will clobber them)
    movaps  xmmword ptr [rsp + XMM_SAVE + 00h], xmm0
    movaps  xmmword ptr [rsp + XMM_SAVE + 10h], xmm1
    movaps  xmmword ptr [rsp + XMM_SAVE + 20h], xmm2
    movaps  xmmword ptr [rsp + XMM_SAVE + 30h], xmm3
    movaps  xmmword ptr [rsp + XMM_SAVE + 40h], xmm4
    movaps  xmmword ptr [rsp + XMM_SAVE + 50h], xmm5

    ; Handler runs with GIF=0 throughout (SimpleSvm model).
    ; Pending interrupts are delivered to guest when VMRUN sets GIF=1.
    ; STGI was stealing guest timer interrupts → freeze.
    ; Call SvmVmexitHandler(VCPU_DATA*, GUEST_CONTEXT*)
    mov     rcx, r13
    mov     rdx, r14
    call    SvmVmexitHandler

    ; Restore guest XMM0-5
    movaps  xmm0, xmmword ptr [rsp + XMM_SAVE + 00h]
    movaps  xmm1, xmmword ptr [rsp + XMM_SAVE + 10h]
    movaps  xmm2, xmmword ptr [rsp + XMM_SAVE + 20h]
    movaps  xmm3, xmmword ptr [rsp + XMM_SAVE + 30h]
    movaps  xmm4, xmmword ptr [rsp + XMM_SAVE + 40h]
    movaps  xmm5, xmmword ptr [rsp + XMM_SAVE + 50h]

    ; Check return value
    test    al, al
    jnz     @@Devirtualize

    jmp     @@Loop

    ; =================================================================
    ;  Guest Entry Point — first VMRUN returns here
    ;  Guest RSP = OriginalRsp (caller's stack with callee-saved regs)
    ;  GIF = 1 (set by VMRUN)
    ; =================================================================
@@GuestEntry:
    ; Pop callee-saved registers from caller's stack and return to DPC
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret

    ; =================================================================
    ;  Devirtualize — must STGI before returning (GIF=0 during handler)
    ; =================================================================
@@Devirtualize:
    ; Re-enable interrupts before returning to OS
    stgi
    ; Restore caller's original RSP (with callee-saved regs pushed)
    mov     rsp, [rsp + FRAME_BELOW + HSL_ORIG_RSP]

    ; Pop callee-saved registers and return
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret

SvmLaunchVm ENDP

; =============================================================================
; Segment selector helpers
; =============================================================================

AsmReadCs PROC
    xor     rax, rax
    mov     ax, cs
    ret
AsmReadCs ENDP

AsmReadSs PROC
    xor     rax, rax
    mov     ax, ss
    ret
AsmReadSs ENDP

AsmReadDs PROC
    xor     rax, rax
    mov     ax, ds
    ret
AsmReadDs ENDP

AsmReadEs PROC
    xor     rax, rax
    mov     ax, es
    ret
AsmReadEs ENDP

END
