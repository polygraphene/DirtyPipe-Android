    .arch armv8-a

    .include "include.inc"

    .global mysyscall
    .global _start
//    .global logerror
    .global libname
    .global root_cmd

    .global c_entry

stage2_data:
    .word 0 // dummy

_start:
    adr x0, L_libname
    adr x1, L_root_cmd
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
L_libname:
    .space 128, 0
root_cmd:
L_root_cmd:
    .space 128, 0

