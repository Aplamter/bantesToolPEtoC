// DLL side of the C++ exception test: throws, and lets exceptions from a
// callback pass through its frames
#include <stdexcept>
#include <string>
#include <cstdio>

struct Guard {
    const char *n;
    Guard(const char *n) : n(n) {}
    ~Guard() { std::printf("  dll: ~Guard(%s)\n", n); }
};

extern "C" __declspec(dllexport) int dll_throws(int x) {
    Guard g("dll_throws");
    if (x > 2) throw std::runtime_error("from the dll: " + std::to_string(x));
    return x * 10;
}

extern "C" __declspec(dllexport) int dll_calls_back(int (*cb)(int), int x) {
    Guard g("dll_calls_back");
    int r = cb(x);              // the callback may throw through here
    std::printf("  dll: callback returned %d\n", r);
    return r + 1;
}

extern "C" __declspec(dllexport) int dll_catches(int (*cb)(int), int x) {
    try {
        return cb(x);
    } catch (const std::exception &e) {
        std::printf("  dll: caught '%s' from the exe callback\n", e.what());
        return -1;
    }
}
