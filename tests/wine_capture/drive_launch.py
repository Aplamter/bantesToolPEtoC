"""run under Windows Python (Wine or real Windows): launch-and-capture the target"""
import json, os, sys
here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(here)))
from recomp.runtime_capture import launch_and_capture
out = sys.argv[1]
s = launch_and_capture(os.path.join(here, "target.exe"), out, delay=2, duration=6, interval=2, log=print)
print(json.dumps(s))
