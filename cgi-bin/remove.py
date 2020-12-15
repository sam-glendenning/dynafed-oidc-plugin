#!/usr/bin/python3.6

# Import modules for CGI handling 
import cgi, cgitb 
import argparse
import sys

CONFIG_PATH = "/etc/ugr/conf.d/"
sys.path.append(CONFIG_PATH)

from manage_oidc_json import remove_bucket

# Create instance of FieldStorage 
form = cgi.FieldStorage() 

# Get data from fields
argument = form.getvalue('argument')
if argument == 'import_bucket':
    group = form.getvalue('group')
    bucket = form.getvalue('bucket')
    public_key = form.getvalue('public_key')
    private_key = form.getvalue('private_key')

    args = argparse.Namespace(group=group, bucket=bucket, public_key=public_key, private_key=private_key, file="/etc/grid-security/oidc_auth.json")

    result = remove_bucket(args)
    if result != 0:
        print('Status: 409 failed to remove')
    else:
        print('Status: 204 success')
else:
    print('Status: 400 bad request')
print()
