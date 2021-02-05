#!/usr/bin/python3.6

"""
Receives information via POST from IRIS DynaFed web UI for removing a bucket
Sends it off to manage_config.py
"""

# Import modules for CGI handling 
import cgi, cgitb 
import argparse
import sys

CONFIG_PATH = "/etc/ugr/conf.d/"
sys.path.append(CONFIG_PATH)

from manage_config import remove_bucket

RETURN_CODES = {
    0: 'Status: 204 success',
    1: 'Status: 500 authorisation config error',
    2: 'Status: 409 bucket does not exist in IRIS DynaFed',
    3: 'Status: 404 bucket does not exist in Echo',
    4: 'Status: 500, cannot synchronise files',
    5: 'Status: 500, cannot synchronise files'
}

# Create instance of FieldStorage 
form = cgi.FieldStorage() 

# Get data from POST fields
if form.getvalue('group') and form.getvalue('bucket') and form.getvalue('public_key') and form.getvalue('private_key') and form.getvalue('groups') and form.getvalue('admin_operation'):
    group = form.getvalue('group')
    bucket = form.getvalue('bucket')
    public_key = form.getvalue('public_key')
    private_key = form.getvalue('private_key')

    # Used for admin purposes. This allows for a bucket removal being performed by an admin to be verified. Ensure they are a member of dynafed/admins AND they're performing the removal request as an admin
    groups = form.getvalue('groups')
    admin_operation = form.getvalue('admin_operation')

    args = argparse.Namespace(group=group, bucket=bucket, public_key=public_key, private_key=private_key, groups=groups, admin_operation=admin_operation, file="/etc/grid-security/oidc_auth.json")

    result = remove_bucket(args)
    print(RETURN_CODES[result])
else:
    print('Status: 400 bad request')
print()
