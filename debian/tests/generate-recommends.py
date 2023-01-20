#!/usr/bin/env python3

import json

with open("extras_require.json") as fh:
    xs = set(f"python3-{x}" for reqs in json.load(fh).values() for x in reqs)

print(", ".join(sorted(xs)))
