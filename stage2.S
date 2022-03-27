    .arch armv8-a

    .include "include.inc"

    .global mysyscall
    .global _start
//    .global logerror
    .global libname

    .global c_entry

stage2_data:
    .word 0 // dummy

_start:
    bl c_entry

exit:
    mov x0, xzr
    mov x8, SYS_exit
    svc 0

mysyscall:
    svc 0
    ret

//logerror:
//    br x0

libname:
    .space 128, 0

