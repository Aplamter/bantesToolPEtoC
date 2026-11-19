// C++ exceptions with the MSVC ABI (__CxxFrameHandler3, _CxxThrowException,
// catch blocks run through STATUS_UNWIND_CONSOLIDATE) - what Unity's
// UnityPlayer.dll and IL2CPP's GameAssembly.dll use. No CRT headers needed.
extern "C" int printf(const char *, ...);
extern "C" __declspec(dllimport) void __stdcall ExitProcess(unsigned);
extern "C" __declspec(dllimport) void __stdcall RaiseException(unsigned, unsigned, unsigned, const unsigned long long *);

// Windows SEH (__try/__except, __C_specific_handler): a real access
// violation in recompiled code, and RaiseException with a custom code
__declspec(noinline) int read_ptr(volatile int *p) { return *p; }
__declspec(noinline) int seh_av(volatile int *p) {
    __try { return read_ptr(p); }
    __except (1) { return -7; }
}
__declspec(noinline) void raise_custom() { RaiseException(0xE0001234, 0, 0, 0); }
__declspec(noinline) unsigned seh_code() {
    unsigned code = 0;
    __try {
        __try { raise_custom(); }
        __except (0) { code = 1; }               // EXCEPTION_CONTINUE_SEARCH: not this one
    }
    __except (code = _exception_code(), 1) { }
    return code;
}
__declspec(noinline) int seh_finally() {
    int x = 0;
    __try {
        __try { x = 1; raise_custom(); }
        __finally { x += 10; }                   // runs during the unwind
    }
    __except (1) { x += 100; }
    return x;
}

static int dtors;
struct Guard {
    const char *n;
    Guard(const char *n) : n(n) {}
    ~Guard() { dtors++; printf("  ~Guard(%s)\n", n); }
};
struct Err { int code; const char *msg; };
struct Derived : Err { int extra; };

__declspec(noinline) void l3(int x) { Guard g("l3"); if (x) throw Err{x, "deep"}; }
__declspec(noinline) void l2(int x) { Guard g("l2"); l3(x); printf("  not reached\n"); }
__declspec(noinline) int l1(int x) { Guard g("l1"); l2(x); return 0; }
__declspec(noinline) void throws_derived() {
    Guard g("derived");
    Derived d;
    d.code = 7; d.msg = "derived"; d.extra = 99;
    throw d;
}

int main() {
    try { throw 42; } catch (int v) { printf("1 caught int %d\n", v); }
    try { l1(5); } catch (const Err &e) { printf("2 caught %s %d, dtors %d\n", e.msg, e.code, dtors); }
    try {
        try { l1(9); } catch (Err &e) { printf("3 inner caught %d, rethrowing\n", e.code); throw; }
    } catch (const Err &e) { printf("3 outer caught %s %d\n", e.msg, e.code); }
    try { throws_derived(); } catch (const Err &e) { printf("4 base caught derived %d\n", e.code); }
    try { throw 3.5; } catch (...) { printf("5 catch(...) took a double\n"); }
    try {
        try { throw Err{1, "first"}; }
        catch (const Err &e) { printf("6 caught %s, throwing second\n", e.msg); throw Err{2, "second"}; }
    } catch (const Err &e) { printf("6 caught %s\n", e.msg); }
    int sum = 0;
    for (int i = 0; i < 100; i++) { try { if (i % 3 == 0) throw i; sum += i; } catch (int v) { sum -= v; } }
    printf("7 loop sum %d, dtors %d\n", sum, dtors);
    int good = 5;
    printf("8 seh: good %d, access violation -> %d\n", seh_av(&good), seh_av((volatile int *)16));
    printf("9 seh: exception code %#x, __finally -> %d\n", seh_code(), seh_finally());
    return 5;
}

extern "C" void start() { ExitProcess(main()); }
// no CRT: the few things it would provide
extern "C" int _fltused = 0;
extern "C" const void *dummy_type_info_vtbl[2] = {0, 0};   // RTTI matches types by name
