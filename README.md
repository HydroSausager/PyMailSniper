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

# В чем отличия от оригинала и прочее
1) Выкачивание папок и писем в файлы формата mbox
2) Нормальный и настраиваемый листинг папок в ящике
3) Многопоточность (dump folders)
4) Красивый tqdm
5) Рабочий поиск по тексту письма с возможность дампа результатов (последние результаты в .txt)
6) Сделай autodiscover запрос или выкачай oab в один клик без бурпа и т.п.
7) Оставь -p пустым чтобы не сохранять пароль в истории
8) Выкачай весь ящик за раз (dump folders -f all -d ... -t ...)
9) Ищи среди ВСЕХ писем и дампь результаты (search emails -f all -d my_folder -t password,пароль,секрет)
10) Поддержка прокси

# Usage
```bash
python3 pymailsniper.py -h
python3 pymailsniper.py dump -h
python3 pymailsniper.py list -h
python3 pymailsniper.py search -h
python3 pymailsniper.py get -h
```

# Avaliable modules:
### General options
```
	-e	--email	your email
	-s	--server	server location (you can find all by "get autodiscover")
	-p	--password	skip for secure input 
	--proxy     Example: socks5://127.0.0.1:9150
```

## List 

### list folder
```
list folders 
	-a 	--absolute	(Print absolute paths) 
	-r 	--root		(Use "root" folder as root for printing insted of "Top Information Store")
	-pc --print-count	(Print count of child folders and email)

```
### list contacts
```
list contacts 
	-v	--verbose	(Print additional info about contacts)
	-g	--gal		(Use GAL instead of "AllAccount" folder)
```
### Notes
	-g	--gal 	IS NOT TESTED

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
	-r	--recurive	( Used when we want to dump all fubfolders 
				of folder specified in --folder arg )

```
### Notes
	'dump folders' and 'dump emails' are equal

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
	-r	--recurive	( Used when we want to search in all fubfolders 
				of folder specified in --folder arg )
```
### Notes
	Search results saves in users folder by default (text)
TODO: 
```
search attachments
```

## Get

## get autodiscover
```
get autodiscover	looks for autodiscover locations, prints saves plain autodiscover.xml response
```
### Note:
	You can use this without -s (--remote-server)
	by default it tries basic auth for possible autodiscover locations, then ntlm 
## get oab
```
get oab				downloads "Offline Address Book" in .lzx format
```
TODO:
```
convert lzx to oab
parse oab
```


