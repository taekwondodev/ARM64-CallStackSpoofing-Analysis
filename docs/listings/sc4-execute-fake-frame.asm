ExecuteWithFakeFrame PROC
    stp     x29, x30, [sp, #-PROLOGUE_SIZE_EXEC]!   ; salva x29/x30 su stack reale
    stp     x19, x20, [sp, #0x10]
    stp     x21, x22, [sp, #0x20]
    stp     x23, x24, [sp, #0x30]
    stp     x25, x26, [sp, #0x40]
    stp     x27, x28, [sp, #0x50]

    mov     x19, sp             ; x19 = SP reale (da ripristinare dopo)
    mov     x20, x29            ; x20 = FP reale
    mov     x21, x0             ; x21 = targetFunc
    mov     x22, x1             ; x22 = fakeFrameData
    mov     x23, x2             ; x23 = parameter
    mov     x24, x30            ; x24 = LR reale

    ldr     x25, [x22, #0x00]   ; x25 = fakeFp
    ldr     x26, [x22, #0x08]   ; x26 = fakeLr  (gadget ntdll)
    ldr     x27, [x22, #0x10]   ; x27 = fakeSp  (top del fake stack)

    mov     sp, x27             ; *** PIVOT: SP ora punta al fake stack ***

    sub     sp, sp, #0x20
    stp     x25, x26, [sp]      ; costruisce frame falso [FP, LR=gadget]
    mov     x29, sp             ; x29 -> frame falso sul fake stack

    mov     x0, x23
    blr     x21                 ; chiama target; x30 = ExecuteWithFakeFrame+0x54

    mov     x28, x0

    mov     sp, x19             ; *** RIPRISTINO: SP torna allo stack reale ***
    mov     x29, x20
    mov     x30, x24
    mov     x0,  x28

    ldp     x27, x28, [sp, #0x50]
    ldp     x25, x26, [sp, #0x40]
    ldp     x23, x24, [sp, #0x30]
    ldp     x21, x22, [sp, #0x20]
    ldp     x19, x20, [sp, #0x10]
    ldp     x29, x30, [sp], #PROLOGUE_SIZE_EXEC
    ret
    ENDP
