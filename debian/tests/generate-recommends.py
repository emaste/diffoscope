#!/usr/bin/env python3

import json

# Load extras_require dict from external JSON file. This allows it to be easily
# shared by the main setup.py script.
with open("extras_require.json") as f:
    extras_require = json.load(f)

xs = set(f"python3-{x}" for reqs in extras_require.values() for x in reqs)

print(", ".join(sorted(xs)))
