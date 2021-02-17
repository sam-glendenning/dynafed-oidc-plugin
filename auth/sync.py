#!/usr/bin/python3.6

"""
A script responsible for synchronising the local DynaFed config directory with a target Echo bucket upstream
The purpose of this is for the Echo bucket to act as a global point of reference for DynaFed hosts behind a load balancer.
The Echo bucket essentially contains the master copy of authorisation rules and bucket config files to be shared across all running DynaFed instances.

The files that are synchronised are:
All files ending in .conf in /etc/ugr/conf.d/ - files containing bucket keys, organised by group
/etc/grid-security/oidc_auth.json - the authorisation rules file, used by oidc_auth.py

usage:
sync.py <action>
"""

import boto3
import json
import os
import ntpath
import argparse
import sys
import pwd
import grp
from botocore.exceptions import ClientError

BUCKET_NAME = 'iris-dynafed-config'     # name of bucket containing the master copy


def setup():
    """
    Establish a connection to the Echo S3 bucket

    :return: a boto3 client for interacting with the bucket
    """

    try:
        with open('/etc/ugr/conf.d/config-bucket-credentials.json', 'r') as file:
            data = json.load(file)
            s3_access_key = data["s3-access-key"]
            s3_secret_key = data["s3-secret-key"]
    except ValueError:
        print("Error: JSON file incorrectly configured. Must contain s3-access-key and s3-secret-key.")
        return None
    except FileNotFoundError:
        print("Error. Could not find /etc/ugr/conf.d/config-bucket-credentials.json.")
        return None

    try:
        conn = boto3.client(
                service_name = 's3',
                aws_access_key_id = s3_access_key,
                aws_secret_access_key = s3_secret_key,
                endpoint_url = 'https://s3.echo.stfc.ac.uk',
                use_ssl=True               # uncomment if you are not using ssl
                )
    except ClientError:
        print("Error: connection to Echo endpoint could not be established. Verify S3 keys and endpoint URL.")
        return None

    return conn

def get():
    """
    Download files from Echo bucket and replace local copies if they exist
    If local directory contains .conf files not present in bucket, delete them
    This method is called every 10 mins by a cron job on the host to keep the host up to date with bucket config

    :returns: 0 for success, non-zero for failure
    """

    conn = setup()
    if not conn:
        print("Failed to sync files.")
        return 1

    # Getting ID numbers for apache user for changing owner of .conf files
    try:
        uid = pwd.getpwnam('apache').pw_uid
        gid = grp.getgrnam('apache').gr_gid
    except KeyError:
        print("Error: apache user undefined. Install the httpd module")
        return 1

    keys = []
    paginator = conn.get_paginator('list_objects_v2')
    pages = paginator.paginate(Bucket=BUCKET_NAME)
    for page in pages:
        for obj in page['Contents']:
            keys.append(obj['Key'])

    # Download files one by one
    for key in keys:
        filepath = '/etc/ugr/conf.d/' + key

        if key == 'oidc_auth.json':     # authorisation rules file
            filepath = '/etc/grid-security/' + key
        elif key == 'blacklist.json':     # blacklist file
            filepath = '/etc/ugr/conf.d/' + key

        try:
            obj = conn.get_object(Bucket=BUCKET_NAME, Key=key)
        except ClientError:
            print("Error: Failed getting objects from upstream")
            return 1

        with open(filepath, 'w') as f:
            f.write(obj['Body'].read().decode('utf-8'))
        os.chown(filepath, uid, gid)        # change owner of file to apache so it can be amended later through the web UI if necessary
        if key == 'oidc_auth.json' or key == 'blacklist.json':
            os.chmod(filepath, 0o646)       # JSON files need 646 permissions to be read from and written to by our Python scripts

    # Deleting .conf files not in bucket
    allfiles = [f for f in os.listdir('/etc/ugr/conf.d/') if os.path.isfile(os.path.join('/etc/ugr/conf.d', f))]
    allfiles = [f for f in allfiles if f.endswith('.conf')]

    for file in allfiles:
        if file not in keys:
            os.remove('/etc/ugr/conf.d/' + file)

    return 0

def put():
    """
    Upload all config files and authorisation rule file to Echo bucket
    Used when a new change through the web UI needs to be published to the master copy

    :returns: 0 for success, non-zero for failure
    """

    conn = setup()
    if not conn:
        print("Failed to sync files.")
        return 1
    
    allfiles = [f for f in os.listdir('/etc/ugr/conf.d/') if os.path.isfile(os.path.join('/etc/ugr/conf.d', f))]
    allfiles = [f for f in allfiles if f.endswith('.conf')]

    for file in allfiles:
        key = ntpath.basename(file)

        try:
            conn.put_object(Body=open('/etc/ugr/conf.d/' + key, 'rb'), Bucket=BUCKET_NAME, Key=key)
        except FileNotFoundError:
            print("Error: could not find or open {} for upload.".format(file))
            return 1

    oidc_auth_json = '/etc/grid-security/oidc_auth.json'
    key = ntpath.basename(oidc_auth_json)

    try:
        conn.put_object(Body=open(oidc_auth_json, 'rb'), Bucket=BUCKET_NAME, Key=key)
    except FileNotFoundError:
        print("Error: could not find or open /etc/grid-security/oidc_auth.json. File does not exist!")
        return 1

    blacklist_json = '/etc/ugr/conf.d/blacklist.json'
    key = ntpath.basename(blacklist_json)

    try:
        conn.put_object(Body=open(blacklist_json, 'rb'), Bucket=BUCKET_NAME, Key=key)
    except FileNotFoundError:
        print("Warning: no blacklist file at /etc/ugr/conf.d/blacklist.json.")

    return 0

def delete_remote_file(path):
    """
    Deletes a file from the Echo bucket. Used if a .conf file is deleted locally, i.e. a group has removed all their buckets

    :param path: the path to the file on the local filesystem
    :returns: 0 for success, non-zero for failure
    """

    conn = setup()
    if not conn:
        print("Failed to delete remote file.")
        return 1
    
    key = ntpath.basename(path)
    conn.delete_object(Bucket=BUCKET_NAME, Key=key)
    return 0


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
