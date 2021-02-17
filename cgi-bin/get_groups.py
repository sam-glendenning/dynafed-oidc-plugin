#!/usr/bin/python3.6

"""
Return a list of all groups
"""

import json
import sys
import argparse

CONFIG_PATH = "/etc/ugr/conf.d/"
sys.path.append(CONFIG_PATH)

from manage_config import get_groups

args = argparse.Namespace(file='/etc/grid-security/oidc_auth.json')
groups = get_groups(args)
groups = [g.replace('-', '/') for g in groups]
groups = [str(g) for g in groups]
groups = sorted(groups)
body = json.dumps(groups)

print("Status: 200 OK")
print("Content-Type: application/json")
print("Content-Length: {}".format(len(body)))
print("")
print(body)
print()
