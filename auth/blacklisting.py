#!/usr/bin/python3.6

import json
from oidc_auth import DEFAULT_AUTH_FILE_LOCATION

BLACKLIST_FILE = "/etc/ugr/conf.d/blacklist.json"

def blacklist_bucket(bucket_name):
    try:
        with open(BLACKLIST_FILE, "r") as f:
            blacklist = json.load(f)
    except FileNotFoundError:
        blacklist = {"buckets": []}

    if bucket_name not in blacklist["buckets"]:
        blacklist["buckets"].append(bucket_name)

    with open(BLACKLIST_FILE, "w") as f:
        json.dump(blacklist, f, indent=4)

def whitelist_bucket(bucket_name):
    try:
        with open(BLACKLIST_FILE, "r") as f:
            blacklist = json.load(f)
    except FileNotFoundError:
        file_json = {"buckets": []}
        with open(BLACKLIST_FILE, "w") as f:
            json.dump(file_json, indent=4)
            return

    if bucket_name in blacklist["buckets"]:
        blacklist["buckets"].remove(bucket_name)

        with open(BLACKLIST_FILE, "w") as f:
            json.dump(blacklist, f, indent=4)

def get_blacklist():
    try:
        with open(BLACKLIST_FILE, "r") as f:
            blacklist = json.load(f)
    except FileNotFoundError:
        return []

    return blacklist["buckets"]
    