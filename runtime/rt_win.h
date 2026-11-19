/* shared between rt_win.c and rt_seh.c */
#pragma once
#include <stdint.h>

#define RT_SENTINEL 0x00007FFFFFFE0000ULL   /* fake return address: "back to the host" */

/* one host->guest call in progress (rt_call_guest), newest first */
typedef struct rt_run_rec {
    struct rt_run_rec *prev;
    void *jb[5];               /* __builtin_setjmp buffer */
    uint64_t entry_sp;         /* guest RSP at entry: the slot holding RT_SENTINEL */
    int depth;
    const void *cont;          /* CONTEXT the guest stack logically continues with, or 0 */
    uint64_t pc;               /* where the run starts / resumes */
} rt_run_rec;

uint64_t rt_call_guest(rt_ctx *c, uint64_t fn, const uint64_t *args4, const uint64_t *stackargs,
                       int nstack, const uint64_t *xmm4, uint64_t *xmm0_out, const void *cont);
rt_ctx *rt_win_ctx(void);
rt_ctx *rt_win_thread_ctx(void);

/* rt_seh.c */
void rt_seh_init(void);
/* a guest call to fn (a native function): 0 = not an exception function,
 * 1 = handled (*pc = where to continue), -1 = failed (crash report follows) */
int rt_seh_intercept(rt_ctx *c, uint64_t fn, const uint64_t *args, uint64_t ret, uint64_t *pc);
long rt_seh_cpu_fault(rt_ctx *c, void *er, void *x, const char *modname);
long rt_guest_veh(rt_ctx *c, void *ep);
