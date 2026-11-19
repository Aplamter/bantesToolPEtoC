/* recomp runtime: Windows x64 exceptions (C++ throw, SEH __try, longjmp)
 * on the GUEST stack.
 *
 * Recompiled code keeps its frames on the guest stack, so Windows' own
 * dispatcher (which walks the real stack) cannot see them. Everything that
 * walks or rewrites frames is therefore emulated here, when the original code
 * calls it:
 *
 *   RaiseException / RtlRaiseException   -> dispatch: walk the guest frames
 *                                            with the guest's .pdata, call
 *                                            each frame's language handler
 *   RtlUnwindEx / RtlUnwind              -> unwind: call termination
 *                                            handlers up to the target frame,
 *                                            then continue there
 *   RtlRestoreContext / NtContinue       -> continue at a context
 *   RtlCaptureContext                    -> the guest registers
 *   RtlLookupFunctionEntry, RtlPcToFileHeader -> guest images
 *   RtlCaptureStackBackTrace             -> guest return addresses
 *
 * The language handlers themselves (__CxxFrameHandler3/4, __C_specific_handler,
 * __gxx_personality_seh0) are ordinary recompiled code. This mirrors
 * RtlDispatchException / RtlUnwindEx, including STATUS_UNWIND_CONSOLIDATE
 * (how MSVC runs catch blocks) and collided unwinds (GCC cleanups).
 *
 * Continuing at a context: the frame that receives control lives in some
 * rt_call_guest() run further up the host stack; we jump back to that run
 * (__builtin_longjmp) with the new registers and it continues from there.
 * Calls this code makes into the guest (handlers, the consolidation
 * callback) record the context their caller logically continues with, so a
 * walk that reaches their RT_SENTINEL return address continues above it.
 */
#define WIN32_LEAN_AND_MEAN
#include "rt_internal.h"
#include "rt_win.h"
#include <windows.h>

#ifndef STATUS_UNWIND_CONSOLIDATE
#define STATUS_UNWIND_CONSOLIDATE 0x80000029
#endif
#ifndef STATUS_UNWIND
#define STATUS_UNWIND 0xC0000027
#endif
#define EXC_NONCONTINUABLE 1
#define EXC_UNWINDING 2
#define EXC_EXIT_UNWIND 4
#define EXC_TARGET_UNWIND 0x20
#define EXC_COLLIDED_UNWIND 0x40

typedef PEXCEPTION_ROUTINE (WINAPI *virtual_unwind_fn)(DWORD, DWORD64, DWORD64, PRUNTIME_FUNCTION,
                                                      PCONTEXT, PVOID *, PDWORD64, PVOID);
static virtual_unwind_fn p_virtual_unwind;

enum { F_RAISE = 1, F_RTLRAISE, F_UNWINDEX, F_UNWIND, F_CAPTURE, F_LOOKUP, F_PCTOFILE,
       F_RESTORE, F_NTCONTINUE, F_BACKTRACE, F_ADDVEH, F_REMVEH, F_ADDVCH, F_REMVCH };
static struct { uint64_t addr; int kind; const char *name; } fns[96];
static int nfns;

/* ---- the program's own vectored exception handlers ------------------------
 * AddVectoredExceptionHandler(first, handler) from recompiled code (Mono does
 * this when it starts) must not reach Windows: the handler is an address in
 * the original, non-executable image. Windows would call it for the very next
 * exception - which is the fault this runtime uses for every callback - fault
 * again inside the dispatcher, call it again... until the stack is gone and
 * the process dies without a word.
 * So the runtime keeps the list itself. Its own handler stays the only real
 * one and offers the exceptions it does not handle to these (rt_guest_veh). */
#define MAX_GVEH 32
static struct { uint64_t fn; uint64_t cookie; } gveh[MAX_GVEH];
static int ngveh;
static uint64_t gveh_next = 0x7EC0DE0000000010ULL;    /* handles we give out */
static CRITICAL_SECTION gveh_cs;
static DWORD gveh_tls = TLS_OUT_OF_INDEXES;           /* "this thread is inside a handler" */

static uint64_t gveh_add(uint64_t first, uint64_t fn) {
    uint64_t cookie = 0;
    EnterCriticalSection(&gveh_cs);
    if (ngveh < MAX_GVEH) {
        int at = first ? 0 : ngveh;
        memmove(&gveh[at + 1], &gveh[at], (ngveh - at) * sizeof gveh[0]);
        cookie = gveh_next;
        gveh_next += 0x10;
        gveh[at].fn = fn;
        gveh[at].cookie = cookie;
        ngveh++;
    }
    LeaveCriticalSection(&gveh_cs);
    return cookie;
}

static uint64_t gveh_remove(uint64_t cookie) {
    uint64_t found = 0;
    EnterCriticalSection(&gveh_cs);
    for (int i = 0; i < ngveh; i++)
        if (gveh[i].cookie == cookie) {
            memmove(&gveh[i], &gveh[i + 1], (ngveh - i - 1) * sizeof gveh[0]);
            ngveh--;
            found = 1;
            break;
        }
    LeaveCriticalSection(&gveh_cs);
    return found;
}

/* called by the runtime's vectored handler for an exception it does not
 * handle itself: the program's handlers, in order. Returns
 * EXCEPTION_CONTINUE_EXECUTION as soon as one says so, else CONTINUE_SEARCH. */
long rt_guest_veh(rt_ctx *c, void *ep) {
    uint64_t list[MAX_GVEH];
    int n;
    if (!ngveh || !c) return EXCEPTION_CONTINUE_SEARCH;
    /* an exception inside one of these handlers must not go to them again */
    if (gveh_tls == TLS_OUT_OF_INDEXES || TlsGetValue(gveh_tls)) return EXCEPTION_CONTINUE_SEARCH;
    EnterCriticalSection(&gveh_cs);
    n = ngveh;
    for (int i = 0; i < n; i++) list[i] = gveh[i].fn;
    LeaveCriticalSection(&gveh_cs);
    long res = EXCEPTION_CONTINUE_SEARCH;
    TlsSetValue(gveh_tls, (LPVOID)1);
    for (int i = 0; i < n; i++) {
        uint64_t a[4] = {(uint64_t)(uintptr_t)ep, 0, 0, 0};
        if (!rt_lookup(c, list[i])) continue;
        long r = (long)(int32_t)rt_call_guest(c, list[i], a, 0, 0, 0, 0, 0);
        if (r == EXCEPTION_CONTINUE_EXECUTION) { res = r; break; }
    }
    TlsSetValue(gveh_tls, 0);
    return res;
}

static void add_fn(HMODULE h, const char *name, int kind) {
    FARPROC f = h ? GetProcAddress(h, name) : 0;
    if (f && nfns < 32) { fns[nfns].addr = (uint64_t)(uintptr_t)f; fns[nfns].kind = kind; fns[nfns].name = name; nfns++; }
}

void rt_seh_init(void) {
    HMODULE nt = GetModuleHandleA("ntdll.dll"), k32 = GetModuleHandleA("kernel32.dll"),
            kb = GetModuleHandleA("kernelbase.dll");
    p_virtual_unwind = (virtual_unwind_fn)GetProcAddress(nt, "RtlVirtualUnwind");
    InitializeCriticalSection(&gveh_cs);
    gveh_tls = TlsAlloc();
    HMODULE all[3] = {nt, k32, kb};
    for (int i = 0; i < 3; i++) {     /* kernel32 forwards most of these to ntdll */
        add_fn(all[i], "RaiseException", F_RAISE);
        add_fn(all[i], "RtlRaiseException", F_RTLRAISE);
        add_fn(all[i], "RtlUnwindEx", F_UNWINDEX);
        add_fn(all[i], "RtlUnwind", F_UNWIND);
        add_fn(all[i], "RtlCaptureContext", F_CAPTURE);
        add_fn(all[i], "RtlLookupFunctionEntry", F_LOOKUP);
        add_fn(all[i], "RtlPcToFileHeader", F_PCTOFILE);
        add_fn(all[i], "RtlRestoreContext", F_RESTORE);
        add_fn(all[i], "NtContinue", F_NTCONTINUE);
        add_fn(all[i], "RtlCaptureStackBackTrace", F_BACKTRACE);
        add_fn(all[i], "AddVectoredExceptionHandler", F_ADDVEH);
        add_fn(all[i], "RtlAddVectoredExceptionHandler", F_ADDVEH);
        add_fn(all[i], "RemoveVectoredExceptionHandler", F_REMVEH);
        add_fn(all[i], "RtlRemoveVectoredExceptionHandler", F_REMVEH);
        add_fn(all[i], "AddVectoredContinueHandler", F_ADDVCH);
        add_fn(all[i], "RtlAddVectoredContinueHandler", F_ADDVCH);
        add_fn(all[i], "RemoveVectoredContinueHandler", F_REMVCH);
        add_fn(all[i], "RtlRemoveVectoredContinueHandler", F_REMVCH);
    }
}

/* ---- guest registers <-> CONTEXT ---------------------------------------- */
static const int xmm_off[16] = {RREG_XMM0, RREG_XMM1, RREG_XMM2, RREG_XMM3, RREG_XMM4, RREG_XMM5,
                                RREG_XMM6, RREG_XMM7, RREG_XMM8, RREG_XMM9, RREG_XMM10, RREG_XMM11,
                                RREG_XMM12, RREG_XMM13, RREG_XMM14, RREG_XMM15};
#define GPRS(X) X(Rax, RAX) X(Rcx, RCX) X(Rdx, RDX) X(Rbx, RBX) X(Rbp, RBP) X(Rsi, RSI) X(Rdi, RDI) \
    X(R8, R8) X(R9, R9) X(R10, R10) X(R11, R11) X(R12, R12) X(R13, R13) X(R14, R14) X(R15, R15)

static void ctx_from_guest(rt_ctx *c, CONTEXT *x, uint64_t rip, uint64_t rsp) {
    memset(x, 0, sizeof *x);
    x->ContextFlags = CONTEXT_FULL | CONTEXT_SEGMENTS;
#define G(f, r) x->f = REG64(c, RREG_##r);
    GPRS(G)
#undef G
    x->Rsp = rsp;
    x->Rip = rip;
    x->EFlags = 0x202 | (c->R[RREG_CF] & 1) | (c->R[RREG_PF] & 1) << 2 | (c->R[RREG_AF] & 1) << 4 |
                (c->R[RREG_ZF] & 1) << 6 | (c->R[RREG_SF] & 1) << 7 | (c->R[RREG_DF] & 1) << 10 |
                (c->R[RREG_OF] & 1) << 11;
    x->MxCsr = x->FltSave.MxCsr = *(uint32_t *)(c->R + RREG_MXCSR);
    x->FltSave.ControlWord = *(uint16_t *)(c->R + RREG_FPUControlWord);
    for (int i = 0; i < 16; i++) memcpy((uint8_t *)&x->Xmm0 + 16 * i, c->R + xmm_off[i], 16);
    x->SegCs = 0x33; x->SegDs = x->SegEs = x->SegSs = x->SegGs = 0x2b; x->SegFs = 0x53;
}

static void guest_from_ctx(rt_ctx *c, const CONTEXT *x) {
#define G(f, r) REG64(c, RREG_##r) = x->f;
    GPRS(G)
#undef G
    REG64(c, RREG_RSP) = x->Rsp;
    c->R[RREG_CF] = x->EFlags & 1;        c->R[RREG_PF] = (x->EFlags >> 2) & 1;
    c->R[RREG_AF] = (x->EFlags >> 4) & 1; c->R[RREG_ZF] = (x->EFlags >> 6) & 1;
    c->R[RREG_SF] = (x->EFlags >> 7) & 1; c->R[RREG_DF] = (x->EFlags >> 10) & 1;
    c->R[RREG_OF] = (x->EFlags >> 11) & 1;
    *(uint32_t *)(c->R + RREG_MXCSR) = x->MxCsr;
    for (int i = 0; i < 16; i++) memcpy(c->R + xmm_off[i], (const uint8_t *)&x->Xmm0 + 16 * i, 16);
}

/* ---- the guest's function tables ----------------------------------------- */
static RUNTIME_FUNCTION *guest_lookup(uint64_t pc, uint64_t *base) {
    rt_module *m = rt_module_of(pc);
    if (!m || !m->pdata) return 0;
    const RUNTIME_FUNCTION *t = m->pdata;
    uint32_t rva = (uint32_t)(pc - m->imagebase);
    int lo = 0, hi = (int)m->npdata - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (rva < t[mid].BeginAddress) hi = mid - 1;
        else if (rva >= t[mid].EndAddress) lo = mid + 1;
        else { *base = m->imagebase; return (RUNTIME_FUNCTION *)&t[mid]; }
    }
    return 0;
}

static rt_run_rec *run_at(rt_ctx *c, uint64_t sentinel_slot) {
    for (rt_run_rec *r = c->seh; r; r = r->prev)
        if (r->entry_sp == sentinel_slot) return r;
    return 0;
}

typedef struct {
    uint64_t pc, base, frame;
    RUNTIME_FUNCTION *fe;
    PEXCEPTION_ROUTINE handler;
    void *hdata;
} frame_t;

/* *ctx is a frame (maybe a RT_SENTINEL return into a run started by this
 * file: then replace it by the context that run continues). 1 = ok, 0 = the
 * stack goes on in native code or ends here */
static int resolve(rt_ctx *c, CONTEXT *ctx) {
    for (int guard = 0; guard < 64 && ctx->Rip == RT_SENTINEL; guard++) {
        rt_run_rec *r = run_at(c, ctx->Rsp - 8);
        if (!r || !r->cont) return 0;
        *ctx = *(const CONTEXT *)r->cont;
    }
    return ctx->Rip != RT_SENTINEL && rt_module_of(ctx->Rip) != 0;
}

/* virtual-unwind the frame *ctx one level (ctx becomes the caller) */
static void unwind_one(CONTEXT *ctx, DWORD type, frame_t *f) {
    f->pc = ctx->Rip;
    f->handler = 0;
    f->hdata = 0;
    f->fe = guest_lookup(f->pc, &f->base);
    if (!f->fe) {                        /* leaf function: return address on top */
        f->frame = ctx->Rsp;
        ctx->Rip = *(uint64_t *)(uintptr_t)ctx->Rsp;
        ctx->Rsp += 8;
        return;
    }
    DWORD64 frame = 0;
    f->handler = p_virtual_unwind(type, f->base, f->pc, f->fe, ctx, &f->hdata, &frame, NULL);
    f->frame = frame;
}

static uint64_t call_handler(rt_ctx *c, PEXCEPTION_ROUTINE h, EXCEPTION_RECORD *rec, uint64_t frame,
                             CONTEXT *ctx, DISPATCHER_CONTEXT *dc, const CONTEXT *cont) {
    uint64_t a[4] = {(uint64_t)(uintptr_t)rec, frame, (uint64_t)(uintptr_t)ctx, (uint64_t)(uintptr_t)dc};
    if (rt_loglevel >= 2)
        rt_log(2, "t%d exception %#lx: handler %#llx %s for frame %#llx (pc %#llx %s)%s", c->tid,
               rec->ExceptionCode, (unsigned long long)(uintptr_t)h, rt_symstr((uint64_t)(uintptr_t)h),
               (unsigned long long)frame, (unsigned long long)dc->ControlPc, rt_symstr(dc->ControlPc),
               rec->ExceptionFlags & EXC_UNWINDING ? " [unwinding]" : "");
    return rt_call_guest(c, (uint64_t)(uintptr_t)h, a, 0, 0, 0, 0, cont);
}

/* ---- continue at a context (never returns) -------------------------------- */
static void resume(rt_ctx *c, CONTEXT *ctx) __attribute__((noreturn));
static void resume(rt_ctx *c, CONTEXT *ctx) {
    rt_run_rec *r = c->seh;
    while (r && r->entry_sp <= ctx->Rsp) r = r->prev;   /* the run whose frames hold ctx */
    if (!r)
        rt_crash(c, "exception handling: the target frame is not in any recompiled code on this "
                 "thread", ctx->Rip, "an unwind/longjmp went past the outermost guest call - probably "
                 "an exception crossing native (non-recompiled) code, which is not supported");
    guest_from_ctx(c, ctx);
    r->pc = ctx->Rip;
    c->cur = ctx->Rip;
    rt_log(2, "t%d continuing at %#llx %s (rsp %#llx)", c->tid, (unsigned long long)ctx->Rip,
           rt_symstr(ctx->Rip), (unsigned long long)ctx->Rsp);
    __builtin_longjmp(r->jb, 1);
}

static void restore_context(rt_ctx *c, CONTEXT *ctx, EXCEPTION_RECORD *rec) __attribute__((noreturn));
static void restore_context(rt_ctx *c, CONTEXT *ctx, EXCEPTION_RECORD *rec) {
    if (rec && rec->ExceptionCode == STATUS_UNWIND_CONSOLIDATE && rec->NumberParameters >= 1) {
        /* MSVC catch blocks: the callback (__CxxCallCatchBlock) runs just
         * below the target frame and returns where to continue */
        static __attribute__((aligned(16))) CONTEXT dummy;
        (void)dummy;
        guest_from_ctx(c, ctx);
        uint64_t a[4] = {(uint64_t)(uintptr_t)rec, 0, 0, 0};
        uint64_t ip = rt_call_guest(c, rec->ExceptionInformation[0], a, 0, 0, 0, 0, ctx);
        ctx->Rip = ip;
    }
    resume(c, ctx);
}

/* ---- dispatch: find a handler for an exception ----------------------------
 * returns 1 if a handler said "continue execution" (*orig may be changed),
 * 0 if nobody handled it. A handler that catches it unwinds and never
 * returns here. */
static int dispatch(rt_ctx *c, EXCEPTION_RECORD *rec, CONTEXT *orig) {
    __attribute__((aligned(16))) CONTEXT ctx = *orig;
    for (int guard = 0; guard < 100000; guard++) {
        if (!resolve(c, &ctx)) return 0;
        frame_t f;
        unwind_one(&ctx, UNW_FLAG_EHANDLER, &f);
        if (!f.handler) continue;
        __attribute__((aligned(16))) DISPATCHER_CONTEXT dc;
        memset(&dc, 0, sizeof dc);
        dc.ControlPc = f.pc; dc.ImageBase = f.base; dc.FunctionEntry = f.fe;
        dc.EstablisherFrame = f.frame; dc.ContextRecord = &ctx; dc.LanguageHandler = f.handler;
        dc.HandlerData = f.hdata;
        /* a handler that catches it starts an unwind from inside itself;
         * above the handler call the stack continues at the raise point */
        uint64_t d = call_handler(c, f.handler, rec, f.frame, orig, &dc, orig);
        switch ((DWORD)d) {
        case ExceptionContinueExecution:
            if (rec->ExceptionFlags & EXC_NONCONTINUABLE)
                rt_crash(c, "exception handling: a handler continued a non-continuable exception",
                         rec->ExceptionCode, "STATUS_NONCONTINUABLE_EXCEPTION");
            return 1;
        case ExceptionContinueSearch:
        case ExceptionNestedException:
            break;
        default:
            rt_crash(c, "exception handling: a handler returned an invalid disposition", d, 0);
        }
    }
    return 0;
}

/* ---- unwind: RtlUnwindEx --------------------------------------------------- */
static void unwind(rt_ctx *c, CONTEXT *start, uint64_t target_frame, uint64_t target_ip,
                   EXCEPTION_RECORD *rec, uint64_t retval, void *history) __attribute__((noreturn));
static void unwind(rt_ctx *c, CONTEXT *start, uint64_t target_frame, uint64_t target_ip,
                   EXCEPTION_RECORD *rec, uint64_t retval, void *history) {
    __attribute__((aligned(16))) CONTEXT ctx = *start, next;
    EXCEPTION_RECORD local;
    if (!rec) {
        memset(&local, 0, sizeof local);
        local.ExceptionCode = STATUS_UNWIND;
        local.ExceptionAddress = (void *)(uintptr_t)ctx.Rip;
        rec = &local;
    }
    rec->ExceptionFlags |= EXC_UNWINDING;
    if (!target_frame) rec->ExceptionFlags |= EXC_EXIT_UNWIND;
    for (int guard = 0; guard < 100000; guard++) {
        if (!resolve(c, &ctx))
            rt_crash(c, "exception handling: the unwind target frame was not found on the guest stack",
                     target_frame, target_frame ? "the frame may belong to native code" :
                     "exit unwind reached the end of the guest stack");
        next = ctx;
        frame_t f;
        unwind_one(&next, UNW_FLAG_UHANDLER, &f);
        if (f.fe && f.frame == target_frame) rec->ExceptionFlags |= EXC_TARGET_UNWIND;
        if (f.handler) {
            __attribute__((aligned(16))) DISPATCHER_CONTEXT dc;
            memset(&dc, 0, sizeof dc);
            dc.ControlPc = f.pc; dc.ImageBase = f.base; dc.FunctionEntry = f.fe;
            /* during an unwind the dispatcher context holds the frame's
             * context *before* its unwind (that is what gets restored for the
             * target frame; GCC sets the landing pad's RDX through it) */
            dc.EstablisherFrame = f.frame; dc.TargetIp = target_ip; dc.ContextRecord = &ctx;
            dc.LanguageHandler = f.handler; dc.HandlerData = f.hdata;
            dc.HistoryTable = history;
            /* a handler may start its own unwind (GCC cleanups do): that
             * one continues with this frame (collided unwind) */
            uint64_t d = call_handler(c, f.handler, rec, f.frame, &ctx, &dc, &ctx);
            rec->ExceptionFlags &= ~(EXC_TARGET_UNWIND | EXC_COLLIDED_UNWIND);
            if ((DWORD)d != ExceptionContinueSearch && (DWORD)d != ExceptionCollidedUnwind)
                rt_crash(c, "exception handling: an unwind handler returned an invalid disposition", d, 0);
        }
        if (f.fe && f.frame == target_frame) break;
        ctx = next;
    }
    if (rec->ExceptionCode != STATUS_UNWIND_CONSOLIDATE) ctx.Rip = target_ip;
    ctx.Rax = retval;
    restore_context(c, &ctx, rec);
}

static void unhandled(rt_ctx *c, EXCEPTION_RECORD *rec) __attribute__((noreturn));
static void unhandled(rt_ctx *c, EXCEPTION_RECORD *rec) {
    char d[400];
    const char *kind = rec->ExceptionCode == 0xE06D7363 ? " (C++ exception, MSVC)"
                     : rec->ExceptionCode == 0x20474343 ? " (C++ exception, GCC)" : "";
    snprintf(d, sizeof d, "exception code %#lx%s raised at %#llx %s and no handler on the guest stack "
             "took it. The original program would terminate here too (unhandled exception)",
             rec->ExceptionCode, kind, (unsigned long long)(uintptr_t)rec->ExceptionAddress,
             rt_symstr((uint64_t)(uintptr_t)rec->ExceptionAddress));
    rt_log(0, "unhandled exception %#lx", rec->ExceptionCode);
    rt_crash(c, "unhandled exception", (uint64_t)(uintptr_t)rec->ExceptionAddress, d);
}

/* ---- the intercepted functions ------------------------------------------- */
static int finish(rt_ctx *c, uint64_t ret, uint64_t rax, uint64_t *pc) {
    REG64(c, RREG_RAX) = rax;
    REG64(c, RREG_RSP) += 8;
    *pc = ret;
    return 1;
}

static void raise_it(rt_ctx *c, EXCEPTION_RECORD *rec, uint64_t ret, uint64_t *pc) {
    __attribute__((aligned(16))) CONTEXT orig;
    ctx_from_guest(c, &orig, ret, REG64(c, RREG_RSP) + 8);   /* the caller, after the call */
    rt_log(2, "t%d raise %#lx at %#llx %s", c->tid, rec->ExceptionCode, (unsigned long long)ret, rt_symstr(ret));
    if (!dispatch(c, rec, &orig)) unhandled(c, rec);
    guest_from_ctx(c, &orig);                              /* handler said: continue */
    *pc = orig.Rip;
}

int rt_seh_intercept(rt_ctx *c, uint64_t fn, const uint64_t *a, uint64_t ret, uint64_t *pc) {
    int kind = 0;
    for (int i = 0; i < nfns; i++) if (fns[i].addr == fn) { kind = fns[i].kind; break; }
    if (!kind) return 0;
    uint64_t sp = REG64(c, RREG_RSP);
    switch (kind) {
    case F_RAISE: {
        EXCEPTION_RECORD rec;
        memset(&rec, 0, sizeof rec);
        rec.ExceptionCode = (DWORD)a[0];
        rec.ExceptionFlags = (DWORD)a[1] & EXC_NONCONTINUABLE;
        rec.ExceptionAddress = (void *)(uintptr_t)ret;
        rec.NumberParameters = (DWORD)a[2] > 15 ? 15 : (DWORD)a[2];
        if (a[3]) memcpy(rec.ExceptionInformation, (void *)(uintptr_t)a[3], 8 * rec.NumberParameters);
        else rec.NumberParameters = 0;
        raise_it(c, &rec, ret, pc);
        return 1;
    }
    case F_RTLRAISE: {
        EXCEPTION_RECORD *rec = (EXCEPTION_RECORD *)(uintptr_t)a[0];
        rec->ExceptionAddress = (void *)(uintptr_t)ret;
        raise_it(c, rec, ret, pc);
        return 1;
    }
    case F_UNWINDEX:
    case F_UNWIND: {
        __attribute__((aligned(16))) CONTEXT start;
        ctx_from_guest(c, &start, ret, sp + 8);
        uint64_t hist = kind == F_UNWINDEX ? *(uint64_t *)(uintptr_t)(sp + 0x30) : 0;
        rt_log(2, "t%d unwind to frame %#llx, ip %#llx %s", c->tid, (unsigned long long)a[0],
               (unsigned long long)a[1], rt_symstr(a[1]));
        unwind(c, &start, a[0], a[1], (EXCEPTION_RECORD *)(uintptr_t)a[2], a[3], (void *)(uintptr_t)hist);
    }
    case F_RESTORE: {
        __attribute__((aligned(16))) CONTEXT x = *(CONTEXT *)(uintptr_t)a[0];
        restore_context(c, &x, (EXCEPTION_RECORD *)(uintptr_t)a[1]);
    }
    case F_NTCONTINUE: {
        __attribute__((aligned(16))) CONTEXT x = *(CONTEXT *)(uintptr_t)a[0];
        restore_context(c, &x, 0);
    }
    case F_CAPTURE: {
        __attribute__((aligned(16))) CONTEXT x;
        ctx_from_guest(c, &x, ret, sp + 8);
        memcpy((void *)(uintptr_t)a[0], &x, sizeof x);
        return finish(c, ret, 0, pc);
    }
    case F_ADDVEH: {
        if (!rt_module_of(a[1])) return 0;                /* a native handler: Windows' business */
        uint64_t h = gveh_add(a[0], a[1]);
        rt_log(1, "t%d the program's vectored exception handler %#llx %s is kept by the runtime (%s)",
               c->tid, (unsigned long long)a[1], rt_symstr(a[1]), a[0] ? "first" : "last");
        return finish(c, ret, h, pc);
    }
    case F_REMVEH: {
        if ((a[0] >> 32) != 0x7EC0DE00u) return 0;        /* not one of ours */
        return finish(c, ret, gveh_remove(a[0]), pc);
    }
    case F_ADDVCH: {
        /* continue handlers only watch: accepted, never called */
        if (!rt_module_of(a[1])) return 0;
        uint64_t h = gveh_next | 8;
        return finish(c, ret, h, pc);
    }
    case F_REMVCH: {
        if ((a[0] >> 32) != 0x7EC0DE00u) return 0;
        return finish(c, ret, 1, pc);
    }
    case F_LOOKUP: {
        uint64_t base = 0;
        RUNTIME_FUNCTION *fe = guest_lookup(a[0], &base);
        if (!rt_module_of(a[0])) return 0;                /* native code: the real one */
        if (a[1]) *(uint64_t *)(uintptr_t)a[1] = base;
        return finish(c, ret, (uint64_t)(uintptr_t)fe, pc);
    }
    case F_PCTOFILE: {
        rt_module *m = rt_module_of(a[0]);
        if (!m) return 0;
        if (a[1]) *(uint64_t *)(uintptr_t)a[1] = m->imagebase;
        return finish(c, ret, m->imagebase, pc);
    }
    case F_BACKTRACE: {
        /* (skip, count, frames, hash): return addresses from the guest stack */
        __attribute__((aligned(16))) CONTEXT x;
        ctx_from_guest(c, &x, ret, sp + 8);
        uint32_t skip = (uint32_t)a[0], n = (uint32_t)a[1], got = 0;
        uint64_t *out = (uint64_t *)(uintptr_t)a[2];
        for (uint32_t i = 0; got < n && i < 1000; i++) {
            if (!resolve(c, &x)) break;
            if (i >= skip) out[got++] = x.Rip;
            frame_t f;
            unwind_one(&x, UNW_FLAG_NHANDLER, &f);
        }
        if (a[3]) *(uint32_t *)(uintptr_t)a[3] = 0;
        return finish(c, ret, got, pc);
    }
    }
    return 0;
}

/* ---- CPU exceptions in recompiled code ----------------------------------
 * Called from the vectored handler. The dispatch itself must not run inside
 * the exception handler, so we redirect the faulting host thread to
 * fault_entry() on a fresh part of its stack and continue there. */
typedef struct { EXCEPTION_RECORD rec; char modname[64]; uint64_t host_rip; } fault_t;

static void fault_entry(fault_t *ft) __attribute__((noreturn, used));
static void fault_entry(fault_t *ft) {
    rt_ctx *c = rt_current_ctx();
    EXCEPTION_RECORD rec = ft->rec;
    char mod[64];
    uint64_t host_rip = ft->host_rip;
    snprintf(mod, sizeof mod, "%s", ft->modname);
    free(ft);
    rec.ExceptionAddress = (void *)(uintptr_t)c->cur;
    __attribute__((aligned(16))) CONTEXT orig;
    ctx_from_guest(c, &orig, c->cur, REG64(c, RREG_RSP));
    if (dispatch(c, &rec, &orig)) resume(c, &orig);         /* handler fixed it: retry */
    const char *what = rec.ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO ? "integer divide by zero"
                     : rec.ExceptionCode == EXCEPTION_INT_OVERFLOW ? "integer overflow"
                     : rec.ExceptionCode == EXCEPTION_STACK_OVERFLOW ? "host stack overflow"
                     : rec.ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION ? "illegal instruction"
                     : rec.ExceptionCode == EXCEPTION_PRIV_INSTRUCTION ? "privileged instruction"
                     : rec.ExceptionInformation[0] == 1 ? "write to invalid memory"
                     : "read from invalid memory";
    char d[400];
    snprintf(d, sizeof d, "%s (host rip %#llx in %s) while running the recompiled instruction below, and "
             "no exception handler of the program took it. If the original program does not crash here, "
             "an earlier instruction computed a wrong value: look at the registers and transfers",
             what, (unsigned long long)host_rip, mod);
    rt_crash(c, "access violation / CPU exception in recompiled code",
             rec.NumberParameters >= 2 ? rec.ExceptionInformation[1] : 0, d);
}

long rt_seh_cpu_fault(rt_ctx *c, void *erp, void *xp, const char *modname) {
    EXCEPTION_RECORD *er = erp;
    CONTEXT *x = xp;
    (void)c;
    fault_t *ft = calloc(1, sizeof *ft);
    ft->rec = *er;
    ft->rec.ExceptionRecord = 0;
    ft->host_rip = x->Rip;
    snprintf(ft->modname, sizeof ft->modname, "%s", modname);
    uint64_t sp = (x->Rsp - 0x4000) & ~15ULL;
    x->Rsp = sp - 8;                     /* as if called */
    x->Rcx = (uint64_t)(uintptr_t)ft;
    x->Rip = (uint64_t)(uintptr_t)fault_entry;
    return EXCEPTION_CONTINUE_EXECUTION;
}
