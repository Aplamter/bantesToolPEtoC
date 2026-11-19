/* recomp runtime for ARM64 shared libraries: moving between native code and
 * recompiled code.
 *
 * Recompiled code keeps the program's registers in memory (the register file
 * ctx->R, laid out like Ghidra's register space) and runs as C on the
 * runtime's own stack. The program's stack is the thread's real stack: sp in
 * the register file is the real sp, so arguments on the stack, alloca and
 * stack unwinding work as in the original.
 *
 *   rt_a64_enter    native code called a function of the program (x16 = its
 *                   address; reached through the jump that replaces the
 *                   function's first instruction): CPU registers -> register
 *                   file, run.
 *   rt_a64_reenter  a native function the program called has returned
 *                   (reached through the BL that replaces the instruction
 *                   after the call; x30 = that place + 4): the same.
 *   (leave)         the program calls, returns to or jumps into native code:
 *                   register file -> CPU registers, jump.
 *
 * Between a leave and the next (re)enter nothing of the runtime is on any
 * stack, so native code may unwind (C++ exceptions, longjmp) as it likes.
 * The register file counts only while sp is on the runtime stack: a signal
 * handler that calls into the program finds out from sp whether it
 * interrupted recompiled code (rt_a64_begin).
 *
 * x18 is never touched (Android keeps the shadow call stack there). */

#define CTX_R     0x00

#define RX        4, lsl #12        /* x registers: R + 0x4000 */
#define RV        5, lsl #12        /* v registers: R + 0x5000, 32 bytes apart */
#define R_SP      8
#define R_FLAGS   0x100

    .text
    .arch armv8-a+fp+simd

/* v0..v31 <- register file (x11 = R + 0x5000) */
.macro LOADV
    ldr q0, [x11, #0]
    ldr q1, [x11, #32]
    ldr q2, [x11, #64]
    ldr q3, [x11, #96]
    ldr q4, [x11, #128]
    ldr q5, [x11, #160]
    ldr q6, [x11, #192]
    ldr q7, [x11, #224]
    ldr q8, [x11, #256]
    ldr q9, [x11, #288]
    ldr q10, [x11, #320]
    ldr q11, [x11, #352]
    ldr q12, [x11, #384]
    ldr q13, [x11, #416]
    ldr q14, [x11, #448]
    ldr q15, [x11, #480]
    ldr q16, [x11, #512]
    ldr q17, [x11, #544]
    ldr q18, [x11, #576]
    ldr q19, [x11, #608]
    ldr q20, [x11, #640]
    ldr q21, [x11, #672]
    ldr q22, [x11, #704]
    ldr q23, [x11, #736]
    ldr q24, [x11, #768]
    ldr q25, [x11, #800]
    ldr q26, [x11, #832]
    ldr q27, [x11, #864]
    ldr q28, [x11, #896]
    ldr q29, [x11, #928]
    ldr q30, [x11, #960]
    ldr q31, [x11, #992]
.endm

/* x0..x15 and x19..x30 <- register file (x10 = R + 0x4000); x9, x10, x11
 * (the pointers into the register file) last. Not x16 and x17: no value is
 * passed in them at a call or a return, and they hold the program's sp and
 * the jump target here. Not x18. */
.macro LOADX
    ldp x0, x1, [x10, #0]
    ldp x2, x3, [x10, #16]
    ldp x4, x5, [x10, #32]
    ldp x6, x7, [x10, #48]
    ldr x8, [x10, #64]
    ldp x12, x13, [x10, #96]
    ldp x14, x15, [x10, #112]
    ldp x19, x20, [x10, #152]
    ldp x21, x22, [x10, #168]
    ldp x23, x24, [x10, #184]
    ldp x25, x26, [x10, #200]
    ldp x27, x28, [x10, #216]
    ldp x29, x30, [x10, #232]
    ldr x11, [x10, #88]
    ldr x9, [x10, #72]
    ldr x10, [x10, #80]
.endm

/* register file <- v0..v7 from a frame at x9 + \off, v8..v15 from the CPU
 * (x12 = R + 0x5000) */
.macro SAVEV8 off
    ldp q0, q1, [x9, #\off]
    ldp q2, q3, [x9, #\off + 0x20]
    ldp q4, q5, [x9, #\off + 0x40]
    ldp q6, q7, [x9, #\off + 0x60]
    str q0, [x12, #0]
    str q1, [x12, #32]
    str q2, [x12, #64]
    str q3, [x12, #96]
    str q4, [x12, #128]
    str q5, [x12, #160]
    str q6, [x12, #192]
    str q7, [x12, #224]
.endm

/* ------------------------------------------------------------------ */
/* native -> program at a function's first instruction. x16 = address of
 * the function, everything else is the caller's: arguments in x0-x7 / v0-v7
 * / on the stack, x8, x30. (Also what a return from a call needs: results,
 * the registers a function preserves.) */
    .globl rt_a64_enter
    .hidden rt_a64_enter
    .type rt_a64_enter, %function
rt_a64_enter:
    sub sp, sp, #0xe0
    stp x0, x1, [sp, #0x00]
    stp x2, x3, [sp, #0x10]
    stp x4, x5, [sp, #0x20]
    stp x6, x7, [sp, #0x30]
    stp x8, x16, [sp, #0x40]
    stp x29, x30, [sp, #0x50]
    stp q0, q1, [sp, #0x60]
    stp q2, q3, [sp, #0x80]
    stp q4, q5, [sp, #0xa0]
    stp q6, q7, [sp, #0xc0]
    add x0, sp, #0xe0                   /* the program's sp = the caller's sp */
    bl rt_a64_begin                     /* x0 = context, x1 = where on the runtime stack to run */
    mov x9, sp
    mov sp, x1                          /* from here on the register file counts */
    ldr x10, [x0, #CTX_R]
    add x11, x10, #RX
    add x12, x10, #RV
    ldp x1, x2, [x9, #0x00]
    stp x1, x2, [x11, #0]
    ldp x1, x2, [x9, #0x10]
    stp x1, x2, [x11, #16]
    ldp x1, x2, [x9, #0x20]
    stp x1, x2, [x11, #32]
    ldp x1, x2, [x9, #0x30]
    stp x1, x2, [x11, #48]
    ldr x1, [x9, #0x40]
    str x1, [x11, #64]
    str x18, [x11, #144]
    stp x19, x20, [x11, #152]
    stp x21, x22, [x11, #168]
    stp x23, x24, [x11, #184]
    stp x25, x26, [x11, #200]
    stp x27, x28, [x11, #216]
    ldp x1, x2, [x9, #0x50]
    stp x1, x2, [x11, #232]             /* x29, x30 */
    SAVEV8 0x60
    str q8, [x12, #256]
    str q9, [x12, #288]
    str q10, [x12, #320]
    str q11, [x12, #352]
    str q12, [x12, #384]
    str q13, [x12, #416]
    str q14, [x12, #448]
    str q15, [x12, #480]
    add x1, x9, #0xe0
    str x1, [x10, #R_SP]
    ldr x1, [x9, #0x48]                 /* the function's address */
.Lrun:                                  /* x0 = context, x1 = address in the program, sp = runtime stack */
    mov x19, x0
    bl rt_a64_run                       /* x0 = the native address the program went to */
    /* program -> native: a call, a return to the caller, a jump */
    mov x17, x0
    ldr x9, [x19, #CTX_R]
    add x10, x9, #RX
    add x11, x9, #RV
    LOADV
    ldr x16, [x9, #R_SP]
    LOADX
    mov sp, x16                         /* (nothing is read from the register file after this) */
    br x17
    .size rt_a64_enter, . - rt_a64_enter

/* ------------------------------------------------------------------ */
/* native -> program at the instruction after a call. x30 = that place + 4;
 * x16 and x17 are on the stack (pushed by the piece of code in front of the
 * image that jumped here). Usually a native function has just returned, but
 * original code that runs as itself can also get here with a jump, so every
 * register and the flags are taken over. */
    .globl rt_a64_reenter
    .hidden rt_a64_reenter
    .type rt_a64_reenter, %function
rt_a64_reenter:
    sub sp, sp, #0x320
    stp x0, x1, [sp, #0x00]
    stp x2, x3, [sp, #0x10]
    stp x4, x5, [sp, #0x20]
    stp x6, x7, [sp, #0x30]
    stp x8, x9, [sp, #0x40]
    stp x10, x11, [sp, #0x50]
    stp x12, x13, [sp, #0x60]
    stp x14, x15, [sp, #0x70]
    add x0, sp, #0x320
    ldp x0, x1, [x0]                    /* x16, x17 */
    stp x0, x1, [sp, #0x80]
    stp x18, x19, [sp, #0x90]
    stp x20, x21, [sp, #0xa0]
    stp x22, x23, [sp, #0xb0]
    stp x24, x25, [sp, #0xc0]
    stp x26, x27, [sp, #0xd0]
    stp x28, x29, [sp, #0xe0]
    mrs x0, nzcv
    stp x30, x0, [sp, #0xf0]
    stp q0, q1, [sp, #0x100]
    stp q2, q3, [sp, #0x120]
    stp q4, q5, [sp, #0x140]
    stp q6, q7, [sp, #0x160]
    stp q8, q9, [sp, #0x180]
    stp q10, q11, [sp, #0x1a0]
    stp q12, q13, [sp, #0x1c0]
    stp q14, q15, [sp, #0x1e0]
    stp q16, q17, [sp, #0x200]
    stp q18, q19, [sp, #0x220]
    stp q20, q21, [sp, #0x240]
    stp q22, q23, [sp, #0x260]
    stp q24, q25, [sp, #0x280]
    stp q26, q27, [sp, #0x2a0]
    stp q28, q29, [sp, #0x2c0]
    stp q30, q31, [sp, #0x2e0]
    add x0, sp, #0x330                  /* the program's sp */
    bl rt_a64_begin
    mov x9, sp
    mov sp, x1
    mov x1, x9
    mov x19, x0
    bl rt_a64_take                      /* (context, frame): frame -> register file; x0 = where to go on */
    mov x1, x0
    mov x0, x19
    b .Lrun
    .size rt_a64_reenter, . - rt_a64_reenter

/* ------------------------------------------------------------------ */
/* uint64_t rt_a64_call_sp(fn, a0, a1, a2, sp): call a function of the
 * program with the program's stack somewhere else than the current stack
 * (signal handlers that interrupt recompiled code, which runs on the
 * runtime stack). x19 carries the real sp through the call: the program
 * preserves it like any function does. */
    .globl rt_a64_call_sp
    .hidden rt_a64_call_sp
    .type rt_a64_call_sp, %function
rt_a64_call_sp:
    stp x29, x30, [sp, #-0x20]!
    str x19, [sp, #0x10]
    mov x19, sp
    mov sp, x4
    mov x16, x0
    mov x0, x1
    mov x1, x2
    mov x2, x3
    bl rt_a64_enter
    mov sp, x19
    ldr x19, [sp, #0x10]
    ldp x29, x30, [sp], #0x20
    ret
    .size rt_a64_call_sp, . - rt_a64_call_sp

/* uint64_t rt_a64_call(fn, a0, a1, a2, a3): call a function of the program
 * from C */
    .globl rt_a64_call
    .hidden rt_a64_call
    .type rt_a64_call, %function
rt_a64_call:
    mov x16, x0
    mov x0, x1
    mov x1, x2
    mov x2, x3
    mov x3, x4
    b rt_a64_enter
    .size rt_a64_call, . - rt_a64_call

/* ------------------------------------------------------------------ */
/* int rt_a64_cas16(uint64_t *p, const uint64_t *expect, uint64_t lo, uint64_t hi)
 * 16-byte compare-and-swap (STXP after LDXP); 1 = stored */
    .globl rt_a64_cas16
    .hidden rt_a64_cas16
    .type rt_a64_cas16, %function
rt_a64_cas16:
    ldp x4, x5, [x1]
1:  ldxp x6, x7, [x0]
    cmp x6, x4
    ccmp x7, x5, #0, eq
    b.ne 2f
    stxp w8, x2, x3, [x0]
    cbnz w8, 1b
    mov w0, #1
    ret
2:  clrex
    mov w0, #0
    ret
    .size rt_a64_cas16, . - rt_a64_cas16

/* ------------------------------------------------------------------ */
/* What the program's TLS descriptors point to: x0 = address of the
 * descriptor; returns in x0 the distance of the variable from the thread
 * pointer and changes nothing else (that is the rule for these functions).
 * Recompiled code doesn't come here - the run loop knows the address and
 * answers itself - only original code that runs as itself does. */
    .globl rt_a64_tlsdesc
    .hidden rt_a64_tlsdesc
    .type rt_a64_tlsdesc, %function
rt_a64_tlsdesc:
    sub sp, sp, #0x2c0
    stp x29, x30, [sp]
    stp x1, x2, [sp, #0x10]
    stp x3, x4, [sp, #0x20]
    stp x5, x6, [sp, #0x30]
    stp x7, x8, [sp, #0x40]
    stp x9, x10, [sp, #0x50]
    stp x11, x12, [sp, #0x60]
    stp x13, x14, [sp, #0x70]
    stp x15, x16, [sp, #0x80]
    mrs x1, nzcv
    stp x17, x1, [sp, #0x90]
    stp q0, q1, [sp, #0xa0]
    stp q2, q3, [sp, #0xc0]
    stp q4, q5, [sp, #0xe0]
    stp q6, q7, [sp, #0x100]
    stp q8, q9, [sp, #0x120]
    stp q10, q11, [sp, #0x140]
    stp q12, q13, [sp, #0x160]
    stp q14, q15, [sp, #0x180]
    stp q16, q17, [sp, #0x1a0]
    stp q18, q19, [sp, #0x1c0]
    stp q20, q21, [sp, #0x1e0]
    stp q22, q23, [sp, #0x200]
    stp q24, q25, [sp, #0x220]
    stp q26, q27, [sp, #0x240]
    stp q28, q29, [sp, #0x260]
    stp q30, q31, [sp, #0x280]
    bl rt_a64_tls_offset
    ldp q0, q1, [sp, #0xa0]
    ldp q2, q3, [sp, #0xc0]
    ldp q4, q5, [sp, #0xe0]
    ldp q6, q7, [sp, #0x100]
    ldp q8, q9, [sp, #0x120]
    ldp q10, q11, [sp, #0x140]
    ldp q12, q13, [sp, #0x160]
    ldp q14, q15, [sp, #0x180]
    ldp q16, q17, [sp, #0x1a0]
    ldp q18, q19, [sp, #0x1c0]
    ldp q20, q21, [sp, #0x1e0]
    ldp q22, q23, [sp, #0x200]
    ldp q24, q25, [sp, #0x220]
    ldp q26, q27, [sp, #0x240]
    ldp q28, q29, [sp, #0x260]
    ldp q30, q31, [sp, #0x280]
    ldp x17, x1, [sp, #0x90]
    msr nzcv, x1
    ldp x1, x2, [sp, #0x10]
    ldp x3, x4, [sp, #0x20]
    ldp x5, x6, [sp, #0x30]
    ldp x7, x8, [sp, #0x40]
    ldp x9, x10, [sp, #0x50]
    ldp x11, x12, [sp, #0x60]
    ldp x13, x14, [sp, #0x70]
    ldp x15, x16, [sp, #0x80]
    ldp x29, x30, [sp]
    add sp, sp, #0x2c0
    ret
    .size rt_a64_tlsdesc, . - rt_a64_tlsdesc

/* One function with unwind information, so the linker gives the library a
 * PT_GNU_EH_FRAME program header. After linking it is pointed at the
 * ORIGINAL image's unwind tables (a64elf.patch_eh_frame_hdr): the return
 * addresses on the program's stack are addresses of the original code. */
    .cfi_sections .eh_frame
    .hidden rt_a64_unwind_anchor
    .type rt_a64_unwind_anchor, %function
rt_a64_unwind_anchor:
    .cfi_startproc
    ret
    .cfi_endproc
    .size rt_a64_unwind_anchor, . - rt_a64_unwind_anchor

    .section .note.GNU-stack,"",%progbits
