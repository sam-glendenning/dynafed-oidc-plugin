#!/usr/bin/python3.6

import json

BLACKLIST_FILE = "/etc/ugr/conf.d/blacklist.json"

def add_to_blacklist(args):

    if (args.bucket is not None and args.admin_operation is not None and args.groups is not None):
        admin_operation = args.admin_operation and "dynafed/admins" in args.groups

        if not admin_operation:
            return 1

        try:
            with open(BLACKLIST_FILE, "r") as f:
                blacklist = json.load(f)
        except FileNotFoundError:
            blacklist = {"buckets": []}

        if args.bucket not in blacklist["buckets"]:
            blacklist["buckets"].append(args.bucket)

        with open(BLACKLIST_FILE, "w") as f:
            json.dump(blacklist, f, indent=4)

            return 0
        else:
            return 2
    else:
        return 1

def remove_from_blacklist(args):

    if (args.bucket is not None and args.admin_operation is not None and args.groups is not None):
        admin_operation = args.admin_operation and "dynafed/admins" in args.groups

        if not admin_operation:
            return 1

        try:
            with open(BLACKLIST_FILE, "r") as f:
                blacklist = json.load(f)
        except FileNotFoundError:
            file_json = {"buckets": []}
            with open(BLACKLIST_FILE, "w") as f:
                json.dump(file_json, indent=4)
                return

        if args.bucket in blacklist["buckets"]:
            blacklist["buckets"].remove(args.bucket)

            with open(BLACKLIST_FILE, "w") as f:
                json.dump(blacklist, f, indent=4)

            return 0
        else:
            return 2
    else:
        return 1

def get_blacklist():
    try:
        with open(BLACKLIST_FILE, "r") as f:
            blacklist = json.load(f)
    except FileNotFoundError:
        return []

    return blacklist["buckets"]
    