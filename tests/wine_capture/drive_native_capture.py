"""run under Windows Python: native output inside native_output_captured() must
be captured (and not reach the console), including a library that caches its
std handle on first use, across several capture blocks"""
import ctypes, os, sys
here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(here)))
from recomp.unity import native_output_captured
lib = ctypes.CDLL(os.path.join(here, "noisy.dll"))
results = []
for block in range(3):
    with native_output_captured() as cap:
        for i in range(2):
            lib.noisy_crt(i); lib.noisy_stderr(i); lib.noisy_win32(i); lib.noisy_cached(i)
    results.append(cap.summary())
print("CONSOLE-AFTER: this line must reach the console", flush=True)
for b, r in enumerate(results):
    for k, v in sorted(r.items()):
        print(f"block{b}: {v}x {k}")
