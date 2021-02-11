#!/usr/bin/python3.6

"""
Receives information via POST from IRIS DynaFed web UI for removing a bucket from blacklist
Sends it off to blacklisting.py
"""

# Import modules for CGI handling 
import cgi 
import argparse
import sys

CONFIG_PATH = "/etc/ugr/conf.d/"
sys.path.append(CONFIG_PATH)

from blacklisting import remove_from_blacklist

RETURN_CODES = {
    0: 'Status: 204 success',
    1: 'Status: 403 unauthorised',
    2: 'Status: 500 cannot synchronise files',
    3: 'Status: 409 resource does not exist',
    4: 'Status: 400 bad request'
}

# Create instance of FieldStorage 
form = cgi.FieldStorage() 

# Get data from POST fields
if form.getvalue('bucket') and form.getvalue('groups[]') and form.getvalue('admin_operation'):
    bucket = form.getvalue('bucket')
    groups = form.getvalue('groups[]')
    admin_operation = form.getvalue('admin_operation')

    args = argparse.Namespace(bucket=bucket, groups=groups, admin_operation=admin_operation)

    result = remove_from_blacklist(args)
    print(RETURN_CODES[result])
else:
    print(RETURN_CODES[3])
print()
