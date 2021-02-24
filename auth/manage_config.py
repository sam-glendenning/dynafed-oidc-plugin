#!/usr/bin/python3.6

"""
Manages the DynaFed bucket config files, adds, amends and removes config files and verifies the oidc_auth.json files
Called by import.py and remove.py when buckets need to be imported or removed
"""

import json
import argparse
import sys
import os
import boto3
from botocore.exceptions import ClientError
from oidc_auth import DEFAULT_AUTH_FILE_LOCATION
import sync
import blacklisting


BLANK_OIDC_AUTH = {
    "prefix": "/gridpp",
    "base_info": [
        {
            "allowed_attributes": [
                {
                    "attribute_requirements": {},
                    "permissions": "l"
                }
            ],
            "propogate_permissions": False
        }
    ],
    "groups": []
}

# needed for python 2 and 3 compabilility to check str types	
try:	
    # python 2 case	
    basestring	
except NameError:	
    # python 3 case	
    basestring = str

def get_oidc_auth():
    if sync.get() != 0:
        print("Synchronisation of files failed.")

    if not os.path.isfile(DEFAULT_AUTH_FILE_LOCATION):
        print("No remote oidc_auth.json file found. Creating new from template.")
        with open(DEFAULT_AUTH_FILE_LOCATION, 'w') as file:
            json.dump(BLANK_OIDC_AUTH, file, indent=4)

def verify(args):
    """
    Verifies the oidc_auth.json file is valid

    :param args: Namespace object containing all arguments given from command line, if any
    :returns: 0 if valid file, non-zero if otherwise
    """

    if args.suppress_verify_output:
        sys.stdout = open(os.devnull, "w")

    try:
        # Check file exists
        with open(args.file, "r") as f:
            config_json = json.load(f)
    except FileNotFoundError:
        get_oidc_auth()
        with open(args.file, "r") as f:
            config_json = json.load(f)
    
    try:
        # Check file has a prefix (corresponds to federation in /etc/httpd/conf.d/zlcgdm-ugr-dav.conf)
        if "prefix" not in config_json:
            print("Federation prefix not specified")
            return 1

        # Check file has a list of groups
        if "groups" not in config_json:
            print("No groups are specified")
            return 1

        # Check groups is actually a list
        if not isinstance(config_json["groups"], list):
            print("Groups should be a list")
            return 1

        # Check validity of group format
        for index, group in enumerate(config_json["groups"]):

            # Check group is a dict of items
            if not isinstance(group, dict):
                print("Groups should be a list of objects, group list index " +
                        str(index) + " is not an object")
                return 1

            # Check group has a name
            if "name" not in group:
                print("No name specified for group list index " +
                    str(index))
                return 1

            # Check validity of buckets assigned to groups
            for index2, bucket in enumerate(group["buckets"]):

                # Check bucket has a name
                if "name" not in bucket:
                    print("No name specified for bucket list index " +
                        str(index2))
                    return 1

                # Check bucket name is a valid string
                if not isinstance(bucket["name"], basestring):
                    print(str(bucket["name"]) + " is not a string, " +
                        "name should be a string for bucket list index " +
                        str(index2))
                    return 1

                # Check if we have a valid value for propogate_permissions
                # propogate_permissions is set to true if we want to grant the given permissions for a path to all its child paths
                if "propogate_permissions" in bucket and not isinstance(bucket["propogate_permissions"], bool):
                    print(str(bucket["propogate_permissions"]) + " is not a bool, " +
                        "propogate_permissions should be a bool for bucket list index " + str(index2))
                    return 1

                # Check bucket has a list of attributes required of the user for them to be authorised access
                if "allowed_attributes" not in bucket:
                    print("No allowed attributes specified for bucket list index " + str(index2))
                    return 1

                # Check the above is in list format
                if not isinstance(bucket["allowed_attributes"], list):
                    print(str(bucket["allowed_attributes"]) + " is not a list, " +
                        "allowed_attributes should be a list for bucket list index " + str(index2))
                    return 1

                # Checking each allowed attribute set in a bucket
                for attr_index, allowed_attributes in enumerate(bucket["allowed_attributes"]):

                    # Check allowed attribute is a dict
                    if not isinstance(allowed_attributes, dict):
                        print("allowed_attributes should be a list of objects, " +
                            "attribute_requirements list index " + str(attr_index) +
                            " endpoint list index " + str(index2) +
                            " has an allowed_attributes list item that is not an object")
                        return 1

                    # Check we have at least one key-value pair for specifying what the attribute needs to be, e.g. attribute: group, value: my-group
                    if "attribute_requirements" not in allowed_attributes:
                        print("No attribute_requirements specified in attribute_requirements list index " +
                            str(attr_index) + " endpoint list index " + str(index2))
                        return 1

                    # Check we have a string of allowed permissions for what the user with the given attributes can do
                    # Currently, only r and l (read and list) are supported as IRIS DynaFed is read-only
                    if "permissions" not in allowed_attributes:
                        print("No permissions specified in attribute_requirements list index " +
                            str(attr_index) + " endpoint list index " + str(index2))
                        return 1

                    # Check each attribute is a dict containing the above
                    if not isinstance(allowed_attributes["attribute_requirements"], dict):
                        print("attribute_requirements should be a dict, in attribute_requirements list index " +
                            str(attr_index) + " endpoint list index " + str(index2))
                        return 1

                    # Validate the format of each attribute
                    if check_valid_attribute_condition(allowed_attributes["attribute_requirements"], attr_index, index) == 1:
                        return 1

                    # use sets to check that only r, l, w and d values are allowed, it does allow for empty permissions
                    if not set(allowed_attributes["permissions"]) <= set([u"r", u"w", u"l", u"d", u"c"]):
                        print("attribute_requirements permissions should be a string " +
                            "containing any of the modes r (read) l (list) w (write) " +
                            "d (delete) c (create), in attribute_requirements list index " +
                            str(attr_index) + " bucket list index " + str(index2))
                        return 1

        print("Config file is valid")
        # restore stdout
        sys.stdout = sys.__stdout__
        return 0
    
    except ValueError as e:
        print("Invalid JSON: {}".format(e)) 
        return 1

def check_valid_attribute_condition(attribute_condition, attr_index, bucket_index):
    """
    Validate an allowed attribute dictionary from the oidc_auth.json file

    :param attribute_condition: the attribute as a dict
    :param attr_index: index of attribute in JSON
    :param bucket_index: index of bucket in JSON
    """

    # Check attribute is a dict
    if not isinstance(attribute_condition, dict):
        print("Atrribute conditions should be dicts, in attribute_requirements list index " +
              str(attr_index) + " endpoint list index " + str(bucket_index))
        return 1

    # empty is valid - means no attributes are required to match
    if len(attribute_condition) == 0:
        return 0

    # Check attribute and value pair are present
    if (("attribute" in attribute_condition and "value" not in attribute_condition) or
       ("value" in attribute_condition and "attribute" not in attribute_condition)):
        print("Atrribute specifications should specify both an attribute name and a value" +
              ", in attribute_requirements list index " + str(attr_index) +
              " endpoint list index " + str(bucket_index))
        return 1

    # Check attribute is a string
    if "attribute" in attribute_condition and not isinstance(attribute_condition["attribute"], basestring):
        print("attribute should be a string, attribute_requirements list index " +
              str(attr_index) + " endpoint list index " + str(bucket_index))
        return 1

    # Check attribute is a pair or an or/and list
    if (("attribute" not in attribute_condition and
         "or" not in attribute_condition and
         "and" not in attribute_condition)):
        print("Atrribute conditions should either be an attribute-value pair, " +
              "or an 'or' condition list or an 'and' condition list" +
              ", in attribute_requirements list index " + str(attr_index) +
              " endpoint list index " + str(bucket_index))
        return 1

    operator = "or" if "or" in attribute_condition else ""
    operator = "and" if "and" in attribute_condition else operator

    # If we have an or/and operator, the corresponding value needs to be a list
    if (operator in attribute_condition and not isinstance(attribute_condition[operator], list)):
        print("OR or AND atrribute conditions should contain a list (of attribute conditions)" +
              ", item in attribute_requirements list index " + str(attr_index) +
              " endpoint list index " + str(bucket_index) + " is not a list")
        return 1

    # Loop for each attribute in the operator list if present
    if (operator in attribute_condition):
        for sub_attribute_condition in attribute_condition[operator]:
            check_valid_attribute_condition(sub_attribute_condition, attr_index, bucket_index)

    return 0

def get_groups(args):
    """
    Retrieve a list of all groups in the JSON

    :param args: Namespace object containing all arguments given from command line, if any
    :return: a list of groups
    """

    args.suppress_verify_output = True
    if verify(args) != 0:
        # restore stdout
        sys.stdout = sys.__stdout__
        print("Config file not valid, please use the verify function to debug")
        return []

    with open(args.file, "r") as f:
        config_json = json.load(f)

    groups = []
    for group in config_json["groups"]:
        groups.append(group["name"])
    return groups

def get_buckets(args):
    """
    Retrieve a list of all buckets in the JSON

    :param args: Namespace object containing all arguments given from command line, if any
    :return: a list of buckets
    """

    args.suppress_verify_output = True
    if verify(args) != 0:
        # restore stdout
        sys.stdout = sys.__stdout__
        print("Config file not valid, please use the verify function to debug")
        return []

    with open(args.file, "r") as f:
        config_json = json.load(f)

    buckets = []
    for group in config_json["groups"]:
        for bucket in group["buckets"]:
            buckets.append(group["name"] + "/" + bucket["name"])
    return buckets

def list_groups(args):
    """
    Print a list of groups in the JSON to stdout

    :param args: Namespace object containing all arguments given from command line, if any
    """

    for group in get_groups(args):
        print(group)

def list_buckets(args):
    """
    Print a list of buckets in the JSON to stdout

    :param args: Namespace object containing all arguments given from command line, if any
    """

    args.suppress_verify_output = True
    if verify(args) != 0:
        # restore stdout
        sys.stdout = sys.__stdout__
        print("Config file not valid, please use the verify function to debug")
        return

    with open(args.file, "r") as f:
        config_json = json.load(f)

    for group in config_json["groups"]:
        print(group["name"] + ":")
        for bucket in group["buckets"]:
            print("\t" + bucket["name"])

def does_group_exist(args):
    """
    Check if group exists in JSON

    :param args: Namespace object containing all arguments given from command line, if any
    :returns: 0 if exists, non-zero if not
    """

    args.suppress_verify_output = True
    if verify(args) != 0:
        # restore stdout
        sys.stdout = sys.__stdout__
        print("Config file not valid, please use the verify function to debug")
        return 1

    sanitised_group = args.group.replace('/', '-')

    with open(args.file, "r") as f:
        config_json = json.load(f)

    for group in config_json["groups"]:
        if group["name"] == sanitised_group:
            return 0
    
    return 1

def does_bucket_exist(args):
    """
    Check if bucket exists in JSON

    :param args: Namespace object containing all arguments given from command line, if any
    :returns: 0 if exists, non-zero if not
    """

    args.suppress_verify_output = True
    if verify(args) != 0:
        # restore stdout
        sys.stdout = sys.__stdout__
        print("Config file not valid, please use the verify function to debug")
        return 1

    sanitised_group = args.group.replace('/', '-')

    with open(args.file, "r") as f:
        config_json = json.load(f)

    for group in config_json["groups"]:
        if group["name"] == sanitised_group:
            for bucket in group["buckets"]:
                if bucket["name"] == args.bucket:
                    return 0
            break

    return 1

def group_info(args):
    """
    Dump JSON fields for given group

    :param args: Namespace object containing all arguments given from command line, if any
    :returns: 0 if success, non-zero if not
    """

    args.suppress_verify_output = True
    if verify(args) != 0:
        # restore stdout
        sys.stdout = sys.__stdout__
        print("Config file not valid, please use the verify function to debug")
        return 1

    with open(args.file, "r") as f:
        config_json = json.load(f)

    for group in config_json["groups"]:
        if group["name"] == args.group:
            print(json.dumps(group, indent=4))
            return 0

    print("No group matching {} found".format(args.group))
    return 1

def bucket_info(args):
    """
    Dump JSON fields for a given bucket

    :param args: Namespace object containing all arguments given from command line, if any
    :returns: 0 if success, non-zero if not
    """

    args.suppress_verify_output = True
    if verify(args) != 0:
        # restore stdout
        sys.stdout = sys.__stdout__
        print("Config file not valid, please use the verify function to debug")
        return 1

    with open(args.file, "r") as f:
        config_json = json.load(f)

    for group in config_json["groups"]:
        if group["name"] == args.group:
            for bucket in group["buckets"]:
                if bucket["name"] == args.bucket:
                    print(json.dumps(bucket, indent=4))
                    return 0
            break

    print("No bucket matching {} found".format(args.bucket))
    return 1

def prefix(args):
    """
    Print the prefix in the auth JSON
    If a prefix argument is specified, replace the prefix in the JSON with the given value

    :param args: Namespace object containing all arguments given from command line, if any
    :returns: 0 if success, non-zero if not
    """

    args.suppress_verify_output = True
    if verify(args) != 0:
        # restore stdout
        sys.stdout = sys.__stdout__
        print("Config file not valid, please use the verify function to debug")
        return 1

    with open(args.file, "r") as f:
        config_json = json.load(f)

    if args.prefix:
        config_json["prefix"] = args.prefix
        with open(args.file, "w") as f:
            json.dump(config_json, f, indent=4)
    else:
        print(config_json["prefix"])
    return 0

def update_bucket_cors(args):
    """
    Grants the correct CORS permissions to all imported buckets from Echo so they can be accessed through DynaFed
    GET is needed at a minimum
    PUT is included despite uploading not working correctly

    :param args: Namespace object containing all arguments given from command line, if any
    :returns: 0 if success, non-zero if not
    """

    try:
        session = boto3.session.Session()
        s3_client = session.client(service_name="s3",
                                endpoint_url="https://s3.echo.stfc.ac.uk",
                                aws_access_key_id=args.public_key,
                                aws_secret_access_key=args.private_key,
                                verify=True)

        cors_rule = {
            "CORSRules": [
                {
                    "AllowedMethods": ["GET", "PUT"],
                    "AllowedOrigins": ["https://dynafed.stfc.ac.uk", "https://dynafed1.gridpp.rl.ac.uk", "https://dynafed2.gridpp.rl.ac.uk", "https://dynafed-test.stfc.ac.uk", "https://dynafed-test1.gridpp.rl.ac.uk", "https://dynafed-test2.gridpp.rl.ac.uk"],
                    "MaxAgeSeconds": 3000
                }
            ]
        }
    
        s3_client.put_bucket_cors(Bucket=args.bucket, CORSConfiguration=cors_rule)
    except ClientError:
        #This can also be because the bucket no longer exists
        print("Error: failed to update bucket CORS rules.")
        return 1

    return 0

def create_bucket_config(args):
    """
    Creates config information for an imported bucket and adds it to the group .conf file that is importing it

    :param args: Namespace object containing all arguments given from command line, if any
    """

    sanitised_group = args.group.replace('/', '-')

    full_bucket_name = sanitised_group + "-" + args.bucket
    bucket_config = [
        "# Plugin for " + args.bucket + " bucket\n",
        "glb.locplugin[]: /usr/lib64/ugr/libugrlocplugin_s3.so " + full_bucket_name + " 15 s3s://s3.echo.stfc.ac.uk/" + args.bucket + "\n",
        "locplugin." + full_bucket_name + ".xlatepfx: /" + sanitised_group + "/" + args.bucket + " /\n",
        "locplugin." + full_bucket_name + ".s3.priv_key: " + args.private_key + "\n",
        "locplugin." + full_bucket_name + ".s3.pub_key: " + args.public_key + "\n",
        "locplugin." + full_bucket_name + ".s3.writable: true\n",
        "locplugin." + full_bucket_name + ".s3.alternate: true\n",
        "locplugin." + full_bucket_name + ".s3.ca_path: /etc/grid-security/certificates/\n",
        "\n"
    ]

    with open("/etc/ugr/conf.d/" + sanitised_group + ".conf", "a") as f:
        f.writelines(bucket_config)

def add_group_to_json(args):
    """
    Add a new group entry to the auth JSON file 

    :param args: Namespace object containing all arguments given from command line, if any
    :returns: 0 if success, non-zero if not
    """

    sanitised_group = args.group.replace('/', '-')
    new_group = {
        "name": sanitised_group,
        "propogate_permissions": False,
        "allowed_attributes": [
			{
            	"attribute_requirements": {}, 
                "permissions": "l"
            }
		],
        "buckets": []
    }

    try:
        with open(args.file, "r") as f:
            config = json.load(f)
    except FileNotFoundError:
        print("Error: could not find given auth JSON file")
        return 1

    config["groups"].append(new_group)

    with open(args.file, "w") as f:
        json.dump(config, f, indent=4)

    return 0

def add_bucket_to_json(args):
    """
    Add a new bucket entry to a given group in the auth JSON file

    :param args: Namespace object containing all arguments given from command line, if any
    :returns: 0 if success, non-zero if not
    """

    if does_bucket_exist(args) == 0:
        print("Error: bucket already exists, use update_bucket_permissions if you want to update it.")
        return 1

    if does_group_exist(args) != 0:
        add_group_to_json(args)

    new_bucket = {
        "name": args.bucket,
        "propogate_permissions": True,
        "allowed_attributes": [],
    }

    # read_groups and write_groups are lists to separate users with read and write permissions on buckets

    if args.read_groups:
        read_groups_config = {
            "attribute_requirements": {
                "or": [],
            },
            "permissions": "rl"
        }

        for read_group in args.read_groups:
            attribute = {
                "attribute": "http.OIDC_CLAIM_groups",
                "value": read_group
            }
            read_groups_config["attribute_requirements"]["or"].append(attribute)

        new_bucket["allowed_attributes"].append(read_groups_config)

    sanitised_group = args.group.replace('/', '-')

    if not args.write_groups:
        args.write_groups = [args.group]

    write_groups_config = {
        "attribute_requirements": {
            "or": [],
        },
        "permissions": "rlwdc"
    }

    for write_group in args.write_groups:
        attribute = {
            "attribute": "http.OIDC_CLAIM_groups",
            "value": write_group
        }
        write_groups_config["attribute_requirements"]["or"].append(attribute)

    new_bucket["allowed_attributes"].append(write_groups_config)

    try:
        with open(args.file, "r") as f:
            config = json.load(f)
    except FileNotFoundError:
        print("Error: could not find given auth JSON file")
        return 1
    
    for group in config["groups"]:
        if group["name"] == sanitised_group:
            config["groups"].remove(group)
            bucket_list = group["buckets"]
            bucket_list.append(new_bucket)
            group["buckets"] = bucket_list
            config["groups"].append(group)
            break

    with open(args.file, "w") as f:
        json.dump(config, f, indent=4)

    return 0

def import_bucket(args):
    """
    Used to import a new bucket into IRIS DynaFed
    Refreshes local copy of files first to make sure config is up to date from remote copy on bucket
    Then creates the necessary config and pushes it to the bucket

    :param args: Namespace object containing all arguments given from command line, if any
    :returns: 0 if success, non-zero if not. Various numbers are returned which will allow for the correct error response to be displayed on the web UI
    """
    
    res_get = sync.get()
    if res_get != 0:
        return 4

    if args.bucket in blacklisting.get_blacklist():
        return 5

    # check config file is valid first
    args.suppress_verify_output = True
    if verify(args) != 0:
        # restore stdout
        sys.stdout = sys.__stdout__
        print("OIDC config file not valid, please use the verify function to debug")
        return 1

    if does_bucket_exist(args) == 0:
        return 2

    # Validate bucket exists in Echo (and update CORS)
    if update_bucket_cors(args) != 0:
        return 3

    create_bucket_config(args)
    add_bucket_to_json(args)

    res_put = sync.put()
    if res_put != 0:
        return 4

    res_get = sync.get()
    if res_get != 0:
        return 4

    return 0

def remove_bucket(args):
    """
    Used to remove a bucket from IRIS DynaFed
    Refreshes local copy of files first to make sure config is up to date from remote copy on bucket
    Then delete the remote config and push updates to bucket

    :param args: Namespace object containing all arguments given from command line, if any
    :returns: 0 if success, non-zero if not. Various numbers are returned which will allow for the correct error response to be displayed on the web UI
    """
    
    res_get = sync.get()
    if res_get != 0:
        return 4
    
    args.suppress_verify_output = True
    if verify(args) != 0:
        # restore stdout
        sys.stdout = sys.__stdout__
        print("Config file not valid, please use the verify function to debug")
        return 1
    
    if does_bucket_exist(args) != 0:
        return 2

    #Potential issue: we need to validate the bucket keys are correct and this is how we do it
    #However, issue with this occurs if the bucket no longer exists in Echo. This currently prevents it from being
    #removed as an entry in DynaFed. 
    #Potential solution: if we are an admin, bypass this keys check. This would mean the user cannot remove a bucket
    #entry that doesn't exist. Not sure how to get around this while keeping the key validation in place
    #TL;DR not a massive issue but still annoying

    if hasattr(args, 'admin_operation') and hasattr(args, 'groups'):
        admin_operation = args.admin_operation and "dynafed/admins" in args.groups
        
        if not admin_operation:
            # Validate bucket exists in Echo
            if update_bucket_cors(args) != 0:
                return 3
    elif update_bucket_cors(args) != 0:
            return 3

    remove_bucket_from_config_file(args)
    remove_bucket_from_json(args)

    res_put = sync.put()
    if res_put != 0:
        return 4

    res_get = sync.get()
    if res_get != 0:
        return 4

    return 0

def remove_bucket_from_json(args):
    """
    Remove a given bucket from the auth JSON file

    :param args: Namespace object containing all arguments given from command line, if any
    :returns: 0 if success, non-zero if not
    """

    sanitised_group = args.group.replace('/', '-')

    with open(args.file, "r") as f:
        config_json = json.load(f)

    for group in config_json["groups"]:
        if group["name"] == sanitised_group:
            for bucket in group["buckets"]:
                if bucket["name"] == args.bucket:
                    config_json["groups"].remove(group)
                    group["buckets"].remove(bucket)
                    if group["buckets"]:        # if no more buckets in group, delete that group
                        config_json["groups"].append(group)
                    with open(args.file, "w") as f:
                        json.dump(config_json, f, indent=4)
                    return 0
            break
    return 1

def remove_bucket_from_config_file(args):
    """
    Remove bucket config info from its group config file

    :param args: Namespace object containing all arguments given from command line, if any
    :returns: 0 if success, non-zero if not
    """

    sanitised_group = args.group.replace('/', '-')
    expected_path = "/etc/ugr/conf.d/{}.conf".format(sanitised_group)
    if not os.path.exists(expected_path):
        return 1

    remaining_config = False

    with open(expected_path, "r") as f:
        lines = f.readlines()
    with open(expected_path, "w") as f:
        for line in lines:
            if args.bucket not in line:
                f.write(line)
                if line and not line.isspace():            # Checking if the line is empty. This is my way of checking that there is other config for other buckets still in the group file
                    remaining_config = True

    # Checking if this was the last bucket in the group, should delete the group if this is the case
    if not remaining_config:
        sync.delete_remote_file(expected_path)
        os.remove(expected_path)
    return 0

def remove_group(args):
    """
    Remove an entire group and its imported buckets. Delete from auth JSON and delete .conf file

    :param args: Namespace object containing all arguments given from command line, if any
    :returns: 0 if success, non-zero if not
    """

    # check config file is valid first
    args.suppress_verify_output = True
    if verify(args) != 0:
        # restore stdout
        sys.stdout = sys.__stdout__
        print("OIDC config file not valid, please use the verify function to debug")
        return 1 

    result_remove_config_file = remove_group_from_json(args)
    result_remove_from_config = remove_group_config_file(args)

    if result_remove_config_file != 0 and result_remove_from_config != 0:
        print("Error. Group {} does not exist in DynaFed".format(args.group))
        return 1

    if result_remove_config_file != 0 or result_remove_from_config != 0:
        print("Error while removing config for {}. Check {} is missing group and {}.conf is missing to ensure full removal.".format(args.group, args.file, args.group))
        return 1
    return 0

def remove_group_from_json(args):
    """
    Remove group info from auth JSON

    :param args: Namespace object containing all arguments given from command line, if any
    :returns: 0 if success, non-zero if not
    """

    sanitised_group = args.group.replace('/', '-')

    with open(args.file, "r") as f:
        config_json = json.load(f)
    
    for group in config_json["groups"]:
        if group["name"] == sanitised_group:
            config_json["groups"].remove(group)
            with open(args.file, "w") as f:
                json.dump(config_json, f, indent=4)
            return 0
    return 1

def remove_group_config_file(args):
    """
    Remove group config file

    :param args: Namespace object containing all arguments given from command line, if any
    :returns: 0 if success, non-zero if not
    """

    sanitised_group = args.group.replace('/', '-')
    expected_path = "/etc/ugr/conf.d/{}.conf".format(sanitised_group)
    if not os.path.exists(expected_path):
        return 1
    os.remove(expected_path)
    return 0

def update_bucket_permissions(args):
    """
    Update permissions a group has on one of its assigned buckets

    :param args: Namespace object containing all arguments given from command line, if any
    :returns: 0 if success, non-zero if not
    """

    if does_bucket_exist(args) != 0:
        print("No bucket matching {} found".format(args.bucket))
        return 1

    result_remove = remove_bucket_from_json(args)
    result_add = add_bucket_to_json(args)
    if result_remove != 0 or result_add != 0:
        print("An unknown error occurred. The bucket is likely misconfigured. Use the verify function to debug.")
        return 1

    return 0

#####################################################

# top level argument parser
parser = argparse.ArgumentParser()

# is this default okay or mark it as a required option?
subparsers = parser.add_subparsers(title="subcommands", description="Functions that can be performed on the JSON file")

# parser for verify command
parser_verify = subparsers.add_parser("verify", help="Verify that the JSON file is valid.")
parser_verify.add_argument("-f, --file", type=str, dest="file", nargs='?', default=DEFAULT_AUTH_FILE_LOCATION, help="Location of the JSON configuration file to act on")
parser_verify.add_argument("--suppress-verify-output", action="store_true", help=argparse.SUPPRESS)  # hidden option to tell us to suppress output
parser_verify.set_defaults(func=verify)

# parser for list groups command
parser_group_list = subparsers.add_parser("list_groups", help="List all groups in file")
parser_group_list.add_argument("-f, --file", type=str, dest="file", nargs='?', default=DEFAULT_AUTH_FILE_LOCATION, help="Location of the JSON configuration file to act on")
parser_group_list.set_defaults(func=list_groups)

# parser for list buckets command
parser_bucket_list = subparsers.add_parser("list_buckets", help="List all buckets in file")
parser_bucket_list.add_argument("-f, --file", type=str, dest="file", nargs='?', default=DEFAULT_AUTH_FILE_LOCATION, help="Location of the JSON configuration file to act on")
parser_bucket_list.set_defaults(func=list_buckets)

# parser for group info command
parser_group_info = subparsers.add_parser("group_info", help="Get the configuration information for a group")
requiredNamed = parser_group_info.add_argument_group('required named arguments')
requiredNamed.add_argument("-g, --group", type=str, required=True, dest="group", help="Group to get info on")
parser_group_info.add_argument("-f, --file", type=str, dest="file", nargs='?', default=DEFAULT_AUTH_FILE_LOCATION, help="Location of the JSON configuration file to act on")
parser_group_info.set_defaults(func=group_info)

# parser for bucket info command
parser_bucket_info = subparsers.add_parser("bucket_info", help="Get the configuration information for a bucket")
requiredNamed = parser_bucket_info.add_argument_group('required named arguments')
requiredNamed.add_argument("-g, --group", type=str, required=True, dest="group", help="Group the bucket belongs to")
requiredNamed.add_argument("-b, --bucket", type=str, required=True, dest="bucket", help="Bucket to get info on")
parser_bucket_info.add_argument("-f, --file", type=str, dest="file", nargs='?', default=DEFAULT_AUTH_FILE_LOCATION, help="Location of the JSON configuration file to act on")
parser_bucket_info.set_defaults(func=bucket_info)

# parser for import_bucket command
parser_import_bucket = subparsers.add_parser("import_bucket", help="Import an S3 bucket by generating the config file for DynaFed and updating the auth file")
requiredNamed = parser_import_bucket.add_argument_group('required named arguments')
requiredNamed.add_argument("-g, --group", type=str, required=True, dest="group", help="Name of the IAM group to associate this bucket with.")
requiredNamed.add_argument("-b, --bucket", type=str, required=True, dest="bucket", help="Name of the S3 bucket you would like to import.")
requiredNamed.add_argument("-f, --file", type=str, dest="file", nargs='?', default=DEFAULT_AUTH_FILE_LOCATION, help="Location of the JSON configuration file to act on")
requiredNamed.add_argument("--public-key", type=str, required=True, dest="public_key", help="AWS access key")
requiredNamed.add_argument("--private-key", type=str, required=True, dest="private_key", help="AWS secret key")
parser_import_bucket.add_argument("--read-groups", dest="read_groups", nargs="+", help="Supply names of groups who should have read and list permissions")
parser_import_bucket.add_argument("--write-groups", dest="write_groups", nargs="+", help="Supply names of groups who should have read, list, write, delete and create permissions")
parser_import_bucket.set_defaults(func=import_bucket)

# parser for remove_bucket command
parser_remove_bucket = subparsers.add_parser("remove_bucket", help="Remove a bucket from the authorisation file")
requiredNamed = parser_remove_bucket.add_argument_group('required named arguments')
requiredNamed.add_argument("-g, --group", type=str, required=True, dest="group", help="Group the bucket belongs to")
requiredNamed.add_argument("-b, --bucket", type=str, required=True, dest="bucket", help="Bucket to remove")
requiredNamed.add_argument("--public-key", type=str, required=True, dest="public_key", help="AWS access key")
requiredNamed.add_argument("--private-key", type=str, required=True, dest="private_key", help="AWS secret key")
parser_remove_bucket.add_argument("-f, --file", type=str, dest="file", nargs='?', default=DEFAULT_AUTH_FILE_LOCATION, help="Location of the JSON configuration file to act on")
parser_remove_bucket.set_defaults(func=remove_bucket)

# parser for remove_group command
parser_remove_group = subparsers.add_parser("remove_group", help="Remove a group and all of its buckets from the authorisation file")
requiredNamed = parser_remove_group.add_argument_group('required named arguments')
requiredNamed.add_argument("-g, --group", type=str, required=True, dest="group", help="Group to remove")
parser_remove_group.add_argument("-f, --file", type=str, dest="file", nargs='?', default=DEFAULT_AUTH_FILE_LOCATION, help="Location of the JSON configuration file to act on")
parser_remove_group.set_defaults(func=remove_group)

# parser for prefix command
parser_prefix = subparsers.add_parser("prefix", help="Get the federation prefix for DynaFed or provide a new prefix. This will be prepended to all endpoints")
parser_prefix.add_argument("-f, --file", type=str, dest="file", nargs='?', default=DEFAULT_AUTH_FILE_LOCATION, help="Location of the JSON configuration file to act on")
parser_prefix.add_argument("-p, --prefix", nargs="?", dest="prefix", help="Supply a prefix to set the federation prefix in the configuration")
parser_prefix.set_defaults(func=prefix)

# parser for update_bucket_permissions command
parser_update_bucket_permissions = subparsers.add_parser("update_bucket_permissions", help="Update the groups that have read and write access to a given bucket. If no groups are specified, only the owning group will have read/write access.")
requiredNamed = parser_update_bucket_permissions.add_argument_group("required named arguments")
requiredNamed.add_argument("-g, --group", type=str, required=True, dest="group", help="Group the bucket belongs to")
requiredNamed.add_argument("-b, --bucket", type=str, required=True, dest="bucket", help="Bucket to update")
parser_update_bucket_permissions.add_argument("-f, --file", type=str, dest="file", nargs='?', default=DEFAULT_AUTH_FILE_LOCATION, help="Location of the JSON configuration file to act on")
parser_update_bucket_permissions.add_argument("--read-groups", dest="read_groups", nargs="+", help="Supply names of groups who should have read and list permissions")
parser_update_bucket_permissions.add_argument("--write-groups", dest="write_groups", nargs="+", help="Supply names of groups who should have read, list, write, delete and create permissions")
parser_update_bucket_permissions.set_defaults(func=update_bucket_permissions)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    else:
        args = parser.parse_args()
        args.func(args)
    sys.exit(0)