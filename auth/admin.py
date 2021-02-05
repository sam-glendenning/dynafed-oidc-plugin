#!/usr/bin/python3.6

import json
from oidc_auth import DEFAULT_AUTH_FILE_LOCATION

BLACKLIST_FILE = "/etc/ugr/conf.d/blacklist.json"

def get_buckets():
    with open(DEFAULT_AUTH_FILE_LOCATION, "r") as f:
        auth_dict = json.load(f)
    
    bucket_dict = {}

    for group in auth_dict["groups"]:
        group_name = group["name"]
        buckets = []
        
        for bucket in group["buckets"]:
            bucket_name = bucket["name"]
            buckets.append(bucket_name)

        bucket_dict[group_name] = buckets

    return bucket_dict

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

    buckets = []
    for bucket in blacklist["buckets"]:
        buckets.append(bucket)
    return buckets
    