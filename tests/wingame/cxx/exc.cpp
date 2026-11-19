// C++ exceptions in recompiled code: same-function, through frames with
// destructors, rethrow, catch(...), nested throw in catch, std library
// exceptions, across a DLL and through DLL frames.
#include <cstdio>
#include <stdexcept>
#include <vector>
#include <string>

extern "C" __declspec(dllimport) int dll_throws(int);
extern "C" __declspec(dllimport) int dll_calls_back(int (*)(int), int);
extern "C" __declspec(dllimport) int dll_catches(int (*)(int), int);

static int dtors;
static bool quiet;
struct Guard {
    const char *n;
    Guard(const char *n) : n(n) {}
    ~Guard() { dtors++; if (!quiet) std::printf("  ~Guard(%s)\n", n); }
};

struct MyError : std::runtime_error {
    int code;
    MyError(const std::string &s, int c) : std::runtime_error(s), code(c) {}
};

__attribute__((noinline)) void level3(int x) { Guard g("level3"); if (x) throw MyError("deep", x); }
__attribute__((noinline)) void level2(int x) { Guard g("level2"); level3(x); std::printf("  not reached\n"); }
__attribute__((noinline)) int level1(int x) { Guard g("level1"); level2(x); return 0; }

static int cb_throw(int x) { if (x == 7) throw MyError("callback", 7); return x * 2; }

int main() {
    // 1. same function
    try { throw 42; } catch (int v) { std::printf("1 caught int %d\n", v); }
    // 2. through three frames with destructors
    try { level1(5); } catch (const MyError &e) { std::printf("2 caught %s code %d, dtors %d\n", e.what(), e.code, dtors); }
    // 3. rethrow
    try {
        try { level1(9); } catch (MyError &e) { std::printf("3 inner caught %d, rethrowing\n", e.code); throw; }
    } catch (const std::exception &e) { std::printf("3 outer caught %s\n", e.what()); }
    // 4. catch(...) on a standard library exception
    try { std::vector<int> v(3); v.at(10) = 1; } catch (...) { std::printf("4 caught out_of_range via catch(...)\n"); }
    // 5. throw inside a catch block
    try {
        try { throw std::logic_error("first"); }
        catch (const std::logic_error &e) { std::printf("5 caught %s, throwing second\n", e.what()); throw std::runtime_error("second"); }
    } catch (const std::runtime_error &e) { std::printf("5 caught %s\n", e.what()); }
    // 6. from the DLL
    std::printf("6 dll_throws(1) = %d\n", dll_throws(1));
    try { dll_throws(5); } catch (const std::runtime_error &e) { std::printf("6 caught '%s'\n", e.what()); }
    // 7. through DLL frames: exe callback throws, DLL frames unwind, exe catches
    try { dll_calls_back(cb_throw, 7); } catch (const MyError &e) { std::printf("7 caught %s through the dll\n", e.what()); }
    std::printf("7 no throw: %d\n", dll_calls_back(cb_throw, 3));
    // 8. the DLL catches what the exe callback throws
    std::printf("8 dll_catches = %d\n", dll_catches(cb_throw, 7));
    // 9. many times (state stays consistent)
    int n = 0;
    quiet = true;
    for (int i = 0; i < 200; i++) { try { level1(i + 1); } catch (const MyError &e) { n += e.code; } }
    std::printf("9 sum %d dtors %d\n", n, dtors);
    return 3;
}
