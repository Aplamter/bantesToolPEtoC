// C++ part of the ARM64 test library: exceptions, virtual calls, templates
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <stdexcept>
#include <memory>

#define EXPORT extern "C" __attribute__((visibility("default")))

namespace {
struct Shape {
    virtual ~Shape() {}
    virtual double area() const = 0;
    virtual const char *name() const { return "shape"; }
};
struct Rect : Shape {
    double w, h;
    Rect(double w_, double h_) : w(w_), h(h_) {}
    double area() const override { return w * h; }
    const char *name() const override { return "rect"; }
};
struct Circle : Shape {
    double r;
    explicit Circle(double r_) : r(r_) {}
    double area() const override { return 3.141592653589793 * r * r; }
};
struct Guard {
    int *n;
    explicit Guard(int *p) : n(p) {}
    ~Guard() { ++*n; }
};

__attribute__((noinline)) int thrower(int depth, int *dtors) {
    Guard g(dtors);
    if (depth == 0) throw std::runtime_error("deep error");
    return thrower(depth - 1, dtors) + 1;
}

__attribute__((noinline)) int checked(const std::vector<int> &v, size_t i) { return v.at(i); }
struct Global { std::string s; Global() : s("static-init") {} } g_global;
}

EXPORT void test_cxx(void) {
    std::vector<std::unique_ptr<Shape>> v;
    v.emplace_back(new Rect(2, 3.5));
    v.emplace_back(new Circle(1.5));
    v.emplace_back(new Rect(10, 0.25));
    double total = 0;
    std::string names;
    for (auto &s : v) { total += s->area(); names += s->name(); names += ','; }
    std::sort(v.begin(), v.end(), [](const std::unique_ptr<Shape> &a, const std::unique_ptr<Shape> &b) {
        return a->area() < b->area();
    });
    std::printf("cxx: total=%.4f names=%s smallest=%s global=%s\n", total, names.c_str(), v[0]->name(),
                g_global.s.c_str());
    std::map<std::string, int> m;
    const char *words[] = {"b", "a", "c", "a", "b", "a"};
    for (auto w : words) m[w]++;
    std::string out;
    for (auto &kv : m) out += kv.first + "=" + std::to_string(kv.second) + " ";
    std::printf("cxx: map=%s\n", out.c_str());
}

EXPORT void test_exceptions(void) {
    int dtors = 0, caught = 0;
    try {
        thrower(10, &dtors);
    } catch (const std::exception &e) {
        caught = (int)std::strlen(e.what());
    }
    int oob = 0;
    std::vector<int> v(3, 7);
    try {
        oob = checked(v, 2);
        oob += checked(v, 5);
    } catch (const std::out_of_range &) {
        oob += 1000;
    }
    int rethrown = 0;
    try {
        try { throw 42; } catch (int x) { rethrown = x; throw; }
    } catch (...) { rethrown += 1; }
    std::printf("exceptions: dtors=%d caught=%d oob=%d rethrown=%d\n", dtors, caught, oob, rethrown);
}
