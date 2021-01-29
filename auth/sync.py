#!/usr/bin/python3.6

import boto3
import json
import os
import ntpath
import argparse
import sys
import pwd
import grp

BUCKET_NAME = 'iris-dynafed-config'

def setup():
    with open('/etc/ugr/conf.d/config-bucket-credentials.json', 'r') as file:
        data = json.load(file)
        s3_access_key = data["s3-access-key"]
        s3_secret_key = data["s3-secret-key"]

    conn = boto3.client(
            service_name = 's3',
            aws_access_key_id = s3_access_key,
            aws_secret_access_key = s3_secret_key,
            endpoint_url = 'https://s3.echo.stfc.ac.uk',
            use_ssl=True               # uncomment if you are not using ssl
            )

    return conn

def get():
    conn = setup()
    uid = pwd.getpwnam('apache').pw_uid
    gid = grp.getgrnam('apache').gr_gid

    keys = []
    paginator = conn.get_paginator('list_objects_v2')
    pages = paginator.paginate(Bucket=BUCKET_NAME)
    for page in pages:
        for obj in page['Contents']:
            keys.append(obj['Key'])

    for key in keys:
        filepath = '/etc/ugr/conf.d/' + key

        if key == 'oidc_auth.json':
            filepath = '/etc/grid-security/' + key

        #try:
        obj = conn.get_object(Bucket=BUCKET_NAME, Key=key)
        with open(filepath, 'w') as f:
            f.write(obj['Body'].read().decode('utf-8'))
        os.chown(filepath, uid, gid)
        #except boto.exception.S3ResponseError as e:
                # got an error and we are not updating an existing file
                # delete the file that was created
        #    print "Failed to update"

    allfiles = [f for f in os.listdir('/etc/ugr/conf.d/') if os.path.isfile(os.path.join('/etc/ugr/conf.d', f))]
    allfiles = [f for f in allfiles if f.endswith('.conf')]

    for file in allfiles:
        if file not in keys:
            os.remove('/etc/ugr/conf.d/' + file)

def put():
    conn = setup()
    allfiles = [f for f in os.listdir('/etc/ugr/conf.d/') if os.path.isfile(os.path.join('/etc/ugr/conf.d', f))]
    allfiles = [f for f in allfiles if f.endswith('.conf')]

    for file in allfiles:
        key = ntpath.basename(file)
        conn.put_object(Body=open('/etc/ugr/conf.d/' + key, 'rb'), Bucket=BUCKET_NAME, Key=key)

    oidc_auth_json = '/etc/grid-security/oidc_auth.json'
    key = ntpath.basename(oidc_auth_json)
    conn.put_object(Body=open(oidc_auth_json, 'rb'), Bucket=BUCKET_NAME, Key=key)

def delete_remote_file(path):
    conn = setup()
    key = ntpath.basename(path)
    conn.delete_object(Bucket=BUCKET_NAME, Key=key)


##################################

parser = argparse.ArgumentParser(description="Sync config files between conf.d and S3 origin")
parser.add_argument('option', nargs='?', help="One of 'get' or 'put'. 'get' updates files from origin, 'put' uploads files to origin")

if __name__ == "__main__":
    if len(sys.argv) == 1:
        get()
        sys.exit(0)

    args = parser.parse_args()
    if args.option == 'get':
        get()
    elif args.option == 'put':
        put()
    else:
        parser.print_help()
        sys.exit(1)
    sys.exit(0)
