#!/usr/bin/python3.6

"""
Receives information via POST from IRIS DynaFed web UI for importing a bucket
Sends it off to manage_config.py
"""

# Import modules for CGI handling 
import cgi 
import argparse
import sys

CONFIG_PATH = "/etc/ugr/conf.d/"
sys.path.append(CONFIG_PATH)

from manage_config import import_bucket

RETURN_CODES = {
    0: 'Status: 201 success',
    1: 'Status: 500 authorisation config error',
    2: 'Status: 409 bucket already exists in IRIS DynaFed',
    3: 'Status: 404 bucket does not exist in Echo',
    4: 'Status: 500, cannot synchronise files',
    5: 'Status: 500, cannot synchronise files'
}

# Create instance of FieldStorage 
form = cgi.FieldStorage() 

# Get data from POST fields
if form.getvalue('group') and form.getvalue('bucket') and form.getvalue('public_key') and form.getvalue('private_key'):
    group = form.getvalue('group')
    bucket = form.getvalue('bucket')
    public_key = form.getvalue('public_key')
    private_key = form.getvalue('private_key')

    read_groups = None
    if form.getvalue('read_groups'):
        read_groups = form.getvalue('read_groups')

    # write_groups gives full permissions to all group members but it doesn't matter because DynaFed is currently read-only. Need to change this in a future release where DynaFed allows writing to buckets
    # So at the moment, read_groups isn't used
    write_groups = [group]
    if form.getvalue('write_groups'):
        for item in form.getvalue('write_groups'):
            write_groups.append(item)

    args = argparse.Namespace(group=group, bucket=bucket, public_key=public_key, private_key=private_key, file="/etc/grid-security/oidc_auth.json", read_groups=read_groups, write_groups=write_groups)

    result = import_bucket(args)
    print(RETURN_CODES[result])
else:
    print('Status: 400 bad request')
print()
