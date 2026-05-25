; SpoofCallStack -- Single-Frame Spoofing (ARM64, MSVC armasm64)
; x0 = targetFunc, x1 = spoofedReturn (ntdll gadget), x2 = param, x3 = realReturnStorage

SpoofCallStack PROC
    ; [1] Normal prologue: save FP, real LR, callee-saved regs
    stp     x29, x30, [sp, #-0x40]!   ; SP -= 0x40; [SP+0]=FP, [SP+8]=real LR
    stp     x19, x20, [sp, #0x10]
    stp     x21, x22, [sp, #0x20]
    stp     x23, x24, [sp, #0x30]
    mov     x29, sp                    ; FP = SpoofCallStack frame base
    mov     x19, x0                    ; x19 = targetFunc
    mov     x20, x1                    ; x20 = ntdll gadget (spoofedReturn)
    mov     x21, x2                    ; x21 = parameter
    mov     x22, x3                    ; x22 = realReturnStorage
    mov     x23, x30                   ; x23 = real LR (backup)
    cbz     x22, SkipStore
    str     x23, [x22]                 ; *realReturnStorage = real LR
SkipStore
    ; [2] Secondary allocation -- NOT in .pdata unwind codes!
    ;     This breaks .pdata-based walkers (WinDbg, ETW).
    sub     sp, sp, #0x30

    ; [3] Build fake frame at [sp+0x20]:
    str     x29, [sp, #0x20]           ; fake FP -> real SpoofCallStack frame
    str     x20, [sp, #0x28]           ; fake LR  = ntdll gadget  <-- KEY

    ; [4] Set x29 to point at the fake frame
    add     x9, sp, #0x20
    mov     x29, x9                    ; x29 -> fake frame (LR = ntdll gadget)

    ; [5] Call target via BLR: x30 overwritten with real return address
    mov     x0, x21
    mov     x30, x20                   ; (overwritten by blr -- irrelevant)
    blr     x19                        ; x30 = SpoofCallStack+0x50 after this

    ; [6] Cleanup and return
    mov     x19, x0
    sub     x29, x29, #0x20
    add     sp, sp, #0x30
    mov     x30, x23                   ; restore real LR
    mov     x0, x19
    ldp     x23, x24, [sp, #0x30]
    ldp     x21, x22, [sp, #0x20]
    ldp     x19, x20, [sp, #0x10]
    ldp     x29, x30, [sp], #0x40
    ret
    ENDP
