#include <windows.h>
__declspec(dllexport) int plugin_data = 3;
__declspec(dllexport) double plugin_scale(double x, int v) { return x * v + 0.25; }
