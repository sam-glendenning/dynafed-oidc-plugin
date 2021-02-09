#!/usr/bin/python3.6

"""
Return a list of all groups
"""

import json
import sys

CONFIG_PATH = "/etc/ugr/conf.d/"
sys.path.append(CONFIG_PATH)

from blacklisting import get_blacklist

buckets = get_blacklist()
buckets = sorted(buckets)
body = json.dumps(buckets)

print("Status: 200 OK")
print("Content-Type: application/json")
print("Content-Length: {}".format(len(body)))
print("")
print(body)
print()
