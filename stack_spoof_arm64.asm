; stack_spoof_arm64_enhanced.asm
;
; Call-Stack Spoofing ARM64 assembly
; Author: Alexander Hagenah (@xaitax)
;
; Platform: Windows on ARM64

    AREA |.text|, CODE, READONLY, ALIGN=4
    
    EXPORT SpoofCallStack
    EXPORT ExecuteWithFakeFrame
    
; --- Symbolic Constants ---
FRAME_SAVE_SIZE         EQU     0x10
NV_REG_PAIRS_SPOOF      EQU     3
NV_REG_SAVE_SPOOF       EQU     NV_REG_PAIRS_SPOOF * 0x10
PROLOGUE_SIZE_SPOOF     EQU     FRAME_SAVE_SIZE + NV_REG_SAVE_SPOOF

NV_REG_PAIRS_EXEC       EQU     5
NV_REG_SAVE_EXEC        EQU     NV_REG_PAIRS_EXEC * 0x10
PROLOGUE_SIZE_EXEC      EQU     FRAME_SAVE_SIZE + NV_REG_SAVE_EXEC

; =================================================================
; SpoofCallStack: Single frame spoofing
; =================================================================
SpoofCallStack PROC
    stp     x29, x30, [sp, #-PROLOGUE_SIZE_SPOOF]!
    stp     x19, x20, [sp, #0x10]
    stp     x21, x22, [sp, #0x20]
    stp     x23, x24, [sp, #0x30]
    mov     x29, sp
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
    mov     x22, x3
    mov     x23, x30
    cbz     x22, SkipStore
    str     x23, [x22]
SkipStore
    sub     sp, sp, #0x30
    str     x29, [sp, #0x20]
    str     x20, [sp, #0x28]
    add     x9, sp, #0x20
    mov     x29, x9
    mov     x0, x21
    mov     x30, x20
    blr     x19
    mov     x19, x0
    sub     x29, x29, #0x20
    add     sp, sp, #0x30
    mov     x30, x23
    mov     x0, x19
    ldp     x23, x24, [sp, #0x30]
    ldp     x21, x22, [sp, #0x20]
    ldp     x19, x20, [sp, #0x10]
    ldp     x29, x30, [sp], #PROLOGUE_SIZE_SPOOF
    ret
    ENDP

; =================================================================
; ExecuteWithFakeFrame: Enhanced with better frame chain setup
; =================================================================
ExecuteWithFakeFrame PROC
    stp     x29, x30, [sp, #-PROLOGUE_SIZE_EXEC]!
    stp     x19, x20, [sp, #0x10]
    stp     x21, x22, [sp, #0x20]
    stp     x23, x24, [sp, #0x30]
    stp     x25, x26, [sp, #0x40]
    stp     x27, x28, [sp, #0x50]
    
    mov     x19, sp
    mov     x20, x29
    mov     x21, x0
    mov     x22, x1
    mov     x23, x2
    mov     x24, x30
    
    ; Load fake frame data
    ldr     x25, [x22, #0x00]
    ldr     x26, [x22, #0x08]
    ldr     x27, [x22, #0x10]
    
    ; Switch to fake stack
    mov     sp, x27
    
    ; Build a proper frame on the fake stack
    sub     sp, sp, #0x20
    stp     x25, x26, [sp]    ; Store fake FP and LR
    mov     x29, sp           ; Set FP to this frame
    
    ; Call target
    mov     x0, x23
    blr     x21
    
    mov     x28, x0           ; Save result
    
    ; Restore real stack
    mov     sp, x19
    mov     x29, x20
    mov     x30, x24
    mov     x0, x28
    
    ldp     x27, x28, [sp, #0x50]
    ldp     x25, x26, [sp, #0x40]
    ldp     x23, x24, [sp, #0x30]
    ldp     x21, x22, [sp, #0x20]
    ldp     x19, x20, [sp, #0x10]
    ldp     x29, x30, [sp], #PROLOGUE_SIZE_EXEC
    ret
    ENDP

    END
