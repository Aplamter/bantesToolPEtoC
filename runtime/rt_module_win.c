/* glue compiled into every rebuilt Windows file: hands its tables to the
 * shared runtime (recomp_rt.dll), which does the rest */
#define WIN32_LEAN_AND_MEAN
#include "rt_internal.h"
#include <windows.h>

BOOL rt_module_dllmain(rt_module *m, HINSTANCE h, DWORD reason, LPVOID reserved);
int rt_module_exemain(rt_module *m);

#ifdef RT_DLL
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
    return rt_module_dllmain(&rt_this_module, h, reason, reserved);
}
#else
int main(void) { return rt_module_exemain(&rt_this_module); }
#endif
