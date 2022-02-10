# Инфо

За основу взят проект от foofus-sph1nx - https://github.com/foofus-sph1nx/PyMailSniper (но от него там почти ничего не осталось)

**TOOL IS UNDER DEVELOPMENT**

**A LOT OF BUGS MAY APPEAR**

# Avaliable options:
## List 
list folders [-a, -r, -pc]
list contacts [-v, --gal] (--gal not tested)
### TODO: list emails (soon)

## Dump
dump folders [-f folder's_name_on_server (all,sent,inbox also supported)] [--dump local_folder] [-t thread_count (1-2 threads is fine)] 
### TODO: dump contacts (simply write to .txt?)
### TODO: dump emails (by passing ids list?) 
### TODO: dump attachments

## Search
search emails [-f folder's_name_on_server (all,sent,inbox also supported)] [--dump local_folder] [--field subject,body] [-t term1,term2,term3]
### TODO: search attachments

## Autodiscover
autodiscover 
### TODO: add multiple auth types, only ntlm for now)

# Что и зачем

Во время пентестов, компрометируя пользователя, никогда не будет лишним изучить его почту, 
но сделать это не всегда просто - трудности возникают при отсутствие GUI, пробрасывании портов и т.п.
Этот форк призван облегчить жизнь пентестерам и прочим личностям, максимально упростив исследование почтовых ящиков на основе MS Exchange.

Создается на основе Exchangelib - (https://github.com/ecederstrand/exchangelib)


PS:
Я не про кодер, пишу в первую очередь для себя, исправления и пожелания приветствуются)

# В чем отличия от оригинала и прочее
1) Выкачивание папок и писем в файлы формата mbox (dump folder, search emails ... --dump ...)
2) Нормальный и настраиваемый листинг папок (list folders)
3) Многопоточность (dump folders ... -t ...)
4) Красивый tqdm
5) Рабочий поиск по тексту письма с возможность дампа результатов (последние результаты в .txt)
6) Сделай autodiscover запрос в один клик без бурпа и т.п.
7) Оставь -p пустым чтобы не сохранять пароль в истории
8) Выкачай весь ящик за раз (dump folders -f all -d ... -t ...)
9) Найди и выкачай ВСЕ письма (search emails -f all -d my_folder -t password,пароль,секрет)

# Usage

python3 pymailsniper.py -h
python3 pymailsniper.py dump -h
python3 pymailsniper.py list -h
python3 pymailsniper.py search -h
python3 pymailsniper.py autodiscover -h


