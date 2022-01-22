# Инфо

За основу взят проект от foofus-sph1nx - https://github.com/foofus-sph1nx/PyMailSniper

# Что и зачем

Во время пентестов, компрометируя пользователя, никогда не будет лишним изучить его почту. Но сделать это не всегда просто - трудности возникают при отсутствие GUI, пробрасывании портов и т.п. Этот форк призван облегчить жизнь максимально упростив исследование почтовых ящиков на основе MS Exchange.

Создается на основе Exchangelib - (https://github.com/ecederstrand/exchangelib)


# Documentation

1. Help Menu
   
   ``` python
   python3 pymailsniper.py -h

      _____       __  __       _ _  _____       _
     |  __ \     |  \/  |     (_) |/ ____|     (_)
     | |__) |   _| \  / | __ _ _| | (___  _ __  _ _ __   ___ _ __
     |  ___/ | | | |\/| |/ _` | | |\___ \| '_ \| | '_ \ / _ \ '__|
     | |   | |_| | |  | | (_| | | |____) | | | | | |_) |  __/ |
     |_|    \__, |_|  |_|\__,_|_|_|_____/|_| |_|_| .__/ \___|_|
             __/ |                               | |
            |___/                                |_|


   # PyMailSniper [http://www.foofus.net] (C) sph1nx Foofus Networks <sph1nx@foofus.net>
   # Fork By HydroSausager

   usage: python3 pymailsniper.py module [options]

   Python implementation of mailsniper

   optional arguments:
     -h, --help            show this help message and exit

   Modules:
     available modules

     {folders,attachment,delegation,emails}
       folders             List Mailbox Folders
       attachment          List/Download Attachments
       delegation          Find where compromised user has access
       emails              Search for Emails

   ```

2. List Folders (Eg. Inbox is in O365)
   ```
   usage: python3 pymailsniper.py module [options] folders [-h] [-s SERVER]
                                                        [-e EMAIL]
                                                        [-p PASSWORD] [-a]
                                                        [-c]

   optional arguments:
     -h, --help            show this help message and exit
     -s SERVER, --remote-server SERVER
                           EWS URL for Mail Server
     -e EMAIL, --email EMAIL
                           Email address of compromised user
     -p PASSWORD, --password PASSWORD
                           Password of compromised user
     -a, --absolute        Print folders absolute paths instead tree if arg is present
     -c, --count           Print count of child folders and email if present

   ```
   Вывести список папок в виде дерева - 
    ```python
    python3 pymailsniper.py folders -s outlook.office365.com -e xyz@domain.com -p Password1
    ```
   Вывести список папок в виде дерева с указанием кол-ва дочерних папок и писем - 
    ```python
    python3 pymailsniper.py folders -c -s outlook.office365.com -e xyz@domain.com -p Password1
    ```
   Вывести список папок (абсолютные пути) - 
    ```python
    python3 pymailsniper.py folders -a -s outlook.office365.com -e xyz@domain.com -p Password1
    ```
   Вывести список папок (абсолютные пути) с указанием кол-ва дочерних папок и писем - 
    ```python
    python3 pymailsniper.py folders -a -c -s outlook.office365.com -e xyz@domain.com -p Password1
    ```

3. Exfiltrate emails

   ```python
    python3 pymailsniper.py emails -s outlook.office365.com -e xyz@domain.com -p Password1 -t vpn,remote,password --field subject -c 100 -o emails.txt
   ```

4. List and/or Download attachments

   ```python
    python3 pymailsniper.py attachment -s outlook.office365.com -e xyz@domain.com -p Password1 -t vpn,remote,password --field subject -c 100 -d l00t
   ```

5. Check if compromised account has delegated rights to any other inboxes

   ```python
    python3 pymailsniper.py attachment -s outlook.office365.com -e xyz@domain.com -p Password1 -g list-of-emails.txt
   ```

# Things to Do

* Add functionality for extracting AD usernames
* Add functionality to dump GAL
