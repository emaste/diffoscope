#!/usr/bin/env python3

from pep517 import meta

from pip._internal.req.constructors import install_req_from_req_string

dist = meta.load(".")

xs = set(
    f"python3-{install_req_from_req_string(x).name}"
    for x in dist.requires
    if install_req_from_req_string(x).markers
)

print(", ".join(sorted(xs)))
