from __future__ import print_function, unicode_literals
import json
import argparse
import sys
import os
import socket
import boto3
from botocore.exceptions import ClientError

# needed for python 2 and 3 compabilility to check str types
try:
    # python 2 case
    basestring
except NameError:
    # python 3 case
    basestring = str

# needed for python 2 and 3 compabilility to get user input
try:
    # python 2 case
    input = raw_input
except NameError:
    # python 3 case
    pass


def verify(args):
    if args.surpress_verify_output:
        sys.stdout = open(os.devnull, "w")

    try:
        with open(args.file, "r") as f:
            config_json = json.load(f)

        if "prefix" not in config_json:
            print("Federation prefix not specified")
            return 1

        if "groups" not in config_json:
            print("No groups are specified")
            return 1

        if not isinstance(config_json["groups"], list):
            print("Groups should be a list")
            return 1

        for index, group in enumerate(config_json["groups"]):
            if not isinstance(group, dict):
                print("Groups should be a list of objects, group list index " +
                        str(index) + " is not an object")
                return 1

            if "name" not in group:
                print("No name specified for group list index " +
                    str(index))
                return 1

            for index2, bucket in enumerate(group["buckets"]):
                if "name" not in bucket:
                    print("No name specified for bucket list index " +
                        str(index2))
                    return 1

                if not isinstance(bucket["name"], basestring):
                    print(str(bucket["name"]) + " is not a string, " +
                        "name should be a string for bucket list index " +
                        str(index2))
                    return 1

                if "propogate_permissions" in bucket and not isinstance(bucket["propogate_permissions"], bool):
                    print(str(bucket["propogate_permissions"]) + " is not a bool, " +
                        "propogate_permissions should be a bool for bucket list index " + str(index2))
                    return 1

                if "allowed_attributes" not in bucket:
                    print("No allowed attributes specified for bucket list index " + str(index2))
                    return 1

                if not isinstance(bucket["allowed_attributes"], list):
                    print(str(bucket["allowed_attributes"]) + " is not a list, " +
                        "allowed_attributes should be a list for bucket list index " + str(index2))
                    return 1

                for attr_index, allowed_attributes in enumerate(bucket["allowed_attributes"]):
                    if not isinstance(allowed_attributes, dict):
                        print("allowed_attributes should be a list of objects, " +
                            "attribute_requirements list index " + str(attr_index) +
                            " endpoint list index " + str(index2) +
                            " has an allowed_attributes list item that is not an object")
                        return 1

                    if "attribute_requirements" not in allowed_attributes:
                        print("No attribute_requirements specified in attribute_requirements list index " +
                            str(attr_index) + " endpoint list index " + str(index2))
                        return 1

                    if "permissions" not in allowed_attributes:
                        print("No permissions specified in attribute_requirements list index " +
                            str(attr_index) + " endpoint list index " + str(index2))
                        return 1

                    if not isinstance(allowed_attributes["attribute_requirements"], dict):
                        print("attribute_requirements should be a dict, in attribute_requirements list index " +
                            str(attr_index) + " endpoint list index " + str(index2))
                        return 1

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
    
    except ValueError:
        print("Invalid JSON") 
        return 1

def get_groups(args):
    args.surpress_verify_output = True
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
    args.surpress_verify_output = True
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
    for group in get_groups(args):
        print(group)

def list_buckets(args):
    args.surpress_verify_output = True
    if verify(args) != 0:
        # restore stdout
        sys.stdout = sys.__stdout__
        print("Config file not valid, please use the verify function to debug")
        return []

    with open(args.file, "r") as f:
        config_json = json.load(f)

    groups = []
    for group in config_json["groups"]:
        print(group["name"] + ":")
        for bucket in group["buckets"]:
            print("\t" + bucket["name"])
    return groups

def check_valid_attribute_condition(attribute_condition, attr_index, bucket_index):
    if not isinstance(attribute_condition, dict):
        print("Atrribute conditions should be dicts, in attribute_requirements list index " +
              str(attr_index) + " endpoint list index " + str(bucket_index))
        return 1

    # empty is valid - means no attributes are required to match
    if len(attribute_condition) == 0:
        return 0

    if (("attribute" in attribute_condition and "value" not in attribute_condition) or
       ("value" in attribute_condition and "attribute" not in attribute_condition)):
        print("Atrribute specifications should specify both an attribute name and a value" +
              ", in attribute_requirements list index " + str(attr_index) +
              " endpoint list index " + str(bucket_index))
        return 1

    if "attribute" in attribute_condition and not isinstance(attribute_condition["attribute"], basestring):
        print("attribute should be a string, attribute_requirements list index " +
              str(attr_index) + " endpoint list index " + str(bucket_index))
        return 1

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

    if (operator in attribute_condition and not isinstance(attribute_condition[operator], list)):
        print("OR or AND atrribute conditions should contain a list (of attribute conditions)" +
              ", item in attribute_requirements list index " + str(attr_index) +
              " endpoint list index " + str(bucket_index) + " is not a list")
        return 1

    if (operator in attribute_condition):
        for sub_attribute_condition in attribute_condition[operator]:
            check_valid_attribute_condition(sub_attribute_condition, attr_index, bucket_index)

    return 0

def group_info(args):
    args.surpress_verify_output = True
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
            break

    print("No group matching {} found".format(args.group))
    return 1

def bucket_info(args):
    args.surpress_verify_output = True
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

def prompt_bool(message):
    while True:
        prompt = input(message).lower()
        true_values = {"t", "true", "y", "yes", "ok"}
        false_values = {"f", "false", "n", "no"}
        if prompt in true_values:
            return True
        elif prompt in false_values:
            return False
        else:
            print("Invalid input, please enter a yes or no response")

def prompt_permissions(message):
    while True:
        permissions = input(message).lower()
        modes = "rlwdc"
        if set(permissions) <= set(modes):
            break
        else:
            print("You entered a character that wasn't r, l, w, d or c, please retry")

    # clean up permission string, make sure no duplicates and sort it in order of rlwdc
    clean_permissions = ""
    if "r" in permissions:
        clean_permissions = "r"
    if "l" in permissions:
        clean_permissions = clean_permissions + "l"
    if "w" in permissions:
        clean_permissions = clean_permissions + "w"
    if "d" in permissions:
        clean_permissions = clean_permissions + "d"
    if "c" in permissions:
        clean_permissions = clean_permissions + "c"

    return clean_permissions

def create_attribute_condition():
    while True:
        user_selection = input("\nWould you like to create an OR condition, AND condition or specify an attribute-value pair? Or would you like to stop adding attribute conditions? \n"
                               "1) OR\n"
                               "2) AND\n"
                               "3) Attribute-value pair\n"
                               "4) Exit\n")
        if (user_selection == "1" or user_selection == "2" or
                user_selection == "3"):
            break
        elif user_selection == "4":
            return {}
        else:
            print("Please enter a number 1-4")

    # OR condition
    if user_selection == "1":
        operation = "or"
        condition = {
            "or": []
        }

    # AND condition
    if user_selection == "2":
        operation = "and"
        condition = {
            "and": []
        }

    # Attribute-value pair
    if user_selection == "3":
        condition = {
            "attribute": "http.OIDC_CLAIM_groups",
            "value": ""
        }

        #value = input("Enter attribute value: ")
        value = input("Enter group name: ")
        condition["value"] = value

        # we can't ask for more conditions, so return
        return condition

    # OR and AND conditions need to ask for sub conditions
    if user_selection == "1" or "user_selection" == 2:
        print("\n\nPlease add an attribute condition to this " + operation.upper() + " condition")

        add_condition = True
        while add_condition:
            # recurse and prompt if they want to add another condition at this level
            attribute_condition = create_attribute_condition()
            # need to check for not {} i.e they selected exit
            if attribute_condition:
                condition[operation].append(attribute_condition)
                add_condition = prompt_bool("Would you like to add another attribute condition to this " +
                                            operation.upper() + " condition? (Y/n)")

    return condition

def prefix(args):
    args.surpress_verify_output = True
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
                "AllowedOrigins": ["https://s3.echo.stfc.ac.uk"],
                "MaxAgeSeconds": 3000
            }
        ]
    }

    try:
        s3_client.put_bucket_cors(Bucket=args.bucket, CORSConfiguration=cors_rule)
    except ClientError as e:
        print("S3 error: {}".format(e))
        return 1

    return 0

def create_bucket_config(args):
    full_bucket_name = args.group + "-" + args.bucket
    bucket_config = [
        "# Plugin for " + args.bucket + " bucket\n",
        "glb.locplugin[]: /usr/lib64/ugr/libugrlocplugin_s3.so " + full_bucket_name + " 15 s3s://s3.echo.stfc.ac.uk/" + args.bucket + "\n",
        "locplugin." + full_bucket_name + ".xlatepfx: /" + args.group + "/" + args.bucket + " /\n",
        "locplugin." + full_bucket_name + ".s3.priv_key: " + args.private_key + "\n",
        "locplugin." + full_bucket_name + ".s3.pub_key: " + args.public_key + "\n",
        "locplugin." + full_bucket_name + ".s3.writable: true\n",
        "locplugin." + full_bucket_name + ".s3.alternate: true\n",
        "locplugin." + full_bucket_name + ".s3.ca_path: /etc/grid-security/certificates/\n",
        "\n"
    ]
    with open("/etc/ugr/conf.d/" + args.group + ".conf", "a") as f:
        f.writelines(bucket_config)

def does_group_exist(args):
    with open(args.file, "r") as f:
        config = json.load(f)

    groups = config["groups"]
    for group in groups:
        if group["name"] == args.group:
            return True
    return False

def add_group_to_config(args):
    new_group = {
        "name": args.group,
        "propogate_permissions": False,
        "allowed_attributes": [
			{
            	"attribute_requirements": {}, 
                "permissions": "l"
            }
		],
        "buckets": []
    }

    with open(args.file, "r") as f:
        config = json.load(f)
    config["groups"].append(new_group)

    with open(args.file, "w") as f:
        json.dump(config, f, indent=4)

def add_bucket_to_config(args):
    if not does_group_exist(args):
        add_group_to_config(args)

    new_bucket = {
        "name": args.bucket,
        "propogate_permissions": True,
        "allowed_attributes": [],
    }

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

    if args.write_groups:
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

    with open(args.file, "r") as f:
        config = json.load(f)
    
    for group in config["groups"]:
        if group["name"] == args.group:
            config["groups"].remove(group)
            bucket_list = group["buckets"]
            bucket_list.append(new_bucket)
            group["buckets"] = bucket_list
            config["groups"].append(group)
            break

    with open(args.file, "w") as f:
        json.dump(config, f, indent=4)

def import_bucket(args):
    # check config file is valid first
    args.surpress_verify_output = True
    if verify(args) != 0:
        # restore stdout
        sys.stdout = sys.__stdout__
        print("OIDC config file not valid, please use the verify function to debug")
        return 1

    if update_bucket_cors(args) != 0:
        return 1

    create_bucket_config(args)
    add_bucket_to_config(args)
    return 0

def remove_bucket(args):
    args.surpress_verify_output = True
    if verify(args) != 0:
        # restore stdout
        sys.stdout = sys.__stdout__
        print("Config file not valid, please use the verify function to debug")
        return 1

    if remove_bucket_from_config(args) != 0 or remove_bucket_from_config_file(args) != 0:
        print("Error while removing config for {}. Check {} is missing bucket and {}.conf is missing bucket config info to ensure full removal.".format(args.bucket, args.file, args.group))
        return 1
    return 0

def remove_bucket_from_config(args):
    with open(args.file, "r") as f:
        config_json = json.load(f)

    for group in config_json["groups"]:
        if group["name"] == args.group:
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
    expected_path = "/etc/ugr/conf.d/{}.conf".format(args.group)
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
        os.remove(expected_path)
    return 0

def remove_group(args):
    # check config file is valid first
    args.surpress_verify_output = True
    if verify(args) != 0:
        # restore stdout
        sys.stdout = sys.__stdout__
        print("OIDC config file not valid, please use the verify function to debug")
        return 1 

    if remove_group_from_config(args) != 0 or remove_group_config_file(args) != 0:
        print("Error while removing config for {}. Check {} is missing group and {}.conf is missing to ensure full removal.".format(args.group, args.file, args.group))
        return 1
    return 0

def remove_group_from_config(args):
    with open(args.file, "r") as f:
        config_json = json.load(f)
    
    for group in config_json["groups"]:
        if group["name"] == args.group:
            config_json["groups"].remove(group)
            with open(args.file, "w") as f:
                json.dump(config_json, f, indent=4)
            return 0
    return 1

def remove_group_config_file(args):
    expected_path = "/etc/ugr/conf.d/{}.conf".format(args.group)
    if not os.path.exists(expected_path):
        return 1
    os.remove(expected_path)
    return 0



# top level argument parser
parser = argparse.ArgumentParser()

# is this default okay or mark it as a required option?
subparsers = parser.add_subparsers(title="subcommands", description="Functions that can be performed on the JSON file")

# parser for verify command
parser_verify = subparsers.add_parser("verify", help="Verify that the JSON file is valid.")
parser_verify.add_argument("-f, --file", type=str, required=True, dest="file", help="Location of the JSON configuration file to act on.")
parser_verify.add_argument("--surpress-verify-output", action="store_true", help=argparse.SUPPRESS)  # hidden option to tell us to surpress output
parser_verify.set_defaults(func=verify)

# parser for list groups command
parser_list = subparsers.add_parser("list_groups", help="List all groups in file")
parser_list.add_argument("-f, --file", type=str, required=True, dest="file", help="Location of the JSON configuration file to act on.")
parser_list.set_defaults(func=list_groups)

# parser for list buckets command
parser_list = subparsers.add_parser("list_buckets", help="List all buckets in file")
parser_list.add_argument("-f, --file", type=str, required=True, dest="file", help="Location of the JSON configuration file to act on.")
parser_list.set_defaults(func=list_buckets)

# parser for group info command
parser_info = subparsers.add_parser("group_info", help="Get the configuration information for a group")
parser_info.add_argument("group", help="Group to get info on")
parser_info.add_argument("-f, --file", type=str, required=True, dest="file", help="Location of the JSON configuration file to act on.")
parser_info.set_defaults(func=group_info)

# parser for bucket info command
parser_info = subparsers.add_parser("bucket_info", help="Get the configuration information for a bucket")
parser_info.add_argument("group", help="Group the bucket belongs to")
parser_info.add_argument("bucket", help="Bucket to get info on")
parser_info.add_argument("-f, --file", type=str, required=True, dest="file", help="Location of the JSON configuration file to act on.")
parser_info.set_defaults(func=bucket_info)

# parser for import_bucket command
parser_import_bucket = subparsers.add_parser("import_bucket", help="Import an S3 bucket by generating the config file for DynaFed")
requiredNamed = parser_import_bucket.add_argument_group('required named arguments')
requiredNamed.add_argument("--group", type=str, required=True, dest="group", help="Name of the IAM group to associate this bucket with.")
requiredNamed.add_argument("--bucket", type=str, required=True, dest="bucket", help="Name of the DynaFed bucket you would like to create.")
requiredNamed.add_argument("--file", type=str, required=True, dest="file", help="Location of the JSON configuration file to act on.")
requiredNamed.add_argument("--public-key", type=str, required=True, dest="public_key", help="AWS access key")
requiredNamed.add_argument("--private-key", type=str, required=True, dest="private_key", help="AWS secret key")
parser_import_bucket.add_argument("--read-groups", dest="read_groups", nargs="+", help="Supply names of groups who should have read and list permissions")
parser_import_bucket.add_argument("--write-groups", dest="write_groups", nargs="+", help="Supply names of groups who should have read, list, write, delete and create permissions")
parser_import_bucket.set_defaults(func=import_bucket)

# parser for remove_bucket command
parser_remove_bucket = subparsers.add_parser("remove_bucket", help="Remove a bucket from the authorisation file")
parser_remove_bucket.add_argument("-f, --file", type=str, required=True, dest="file", help="Location of the JSON configuration file to act on.")
parser_remove_bucket.add_argument("group", help="Group the bucket belongs to")
parser_remove_bucket.add_argument("bucket", help="Bucket to remove from authorisation file")
parser_remove_bucket.set_defaults(func=remove_bucket)

# parser for remove_group command
parser_remove_group = subparsers.add_parser("remove_group", help="Remove a group and all of its buckets from the authorisation file")
parser_remove_group.add_argument("-f, --file", type=str, required=True, dest="file", help="Location of the JSON configuration file to act on.")
parser_remove_group.add_argument("group", help="Group to remove")
parser_remove_group.set_defaults(func=remove_group)

# parser for prefix command
parser_prefix = subparsers.add_parser("prefix", help="Get the federation prefix for DynaFed or provide a new prefix. This will be prepended to all endpoints")
parser_prefix.add_argument("-f, --file", type=str, required=True, dest="file", help="Location of the JSON configuration file to act on.")
parser_prefix.add_argument("prefix", nargs="?", help="Supply a prefix to set the federation prefix in the configuration")
parser_prefix.set_defaults(func=prefix)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    else:
        args = parser.parse_args()
        args.func(args)