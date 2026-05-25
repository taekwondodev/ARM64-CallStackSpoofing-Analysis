; SecretFunction prologue -- captured at breakpoint entry
; Address: 0x00007FF71DFEB810
; Frame size: 0x60 bytes (96 bytes)

stack_spoof!SecretFunction:
00007ff7`1dfeb810  a9ba53f3  stp  x19, x20, [sp, #-0x60]!
; ^ Pre-index: SP -= 0x60, then store x19 at [SP+0], x20 at [SP+8]
; Subsequent prologue instructions save x29 (FP) and x30 (LR),
; then set x29 = SP to establish the frame pointer chain.
