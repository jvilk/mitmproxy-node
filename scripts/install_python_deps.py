#!/usr/bin/env python3
"""
Sanity checks the Python environment
"""
import sys
from subprocess import check_call, check_output

# Check Python version
if sys.version_info < (3,6):
    sys.exit("mitmproxy-node requires a Python version >= 3.6, but found {}.{}".format(sys.version_info[0], sys.version_info[1]))

# Verify that mitmproxy is installed
try:
    mitmdump_output = str(check_output(["mitmdump", "--version"]))
    version = mitmdump_output.split("\\n")[0].split(" ")[1].split('.')
    print(version)
    version[0] = int(version[0])
    version[1] = int(version[1])
    version[2] = int(version[2])
    if tuple(version) < (4,0,0):
        sys.exit("mitmproxy-node requires mitmproxy >= 4.0.0, but found {}.{}.{}".format(version[0], version[1], version[2]))
except FileNotFoundError:
    sys.exit("mitmproxy-node requires mitmproxy to be installed. See http://docs.mitmproxy.org/en/stable/install.html for instructions.")

# Install dependencies with pip3 first.
# If pip3 isn't found, use pip.
try:
    check_call(["pip3", "install", "-r", "requirements.txt"])
except FileNotFoundError:
    check_call(["pip", "install", "-r", "requirements.txt"])
