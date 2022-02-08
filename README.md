# Инфо

За основу взят проект от foofus-sph1nx - https://github.com/foofus-sph1nx/PyMailSniper (но от него там почти ничего не осталось)

**TOOL IS UNDER DEVELOPMENT**

**A LOT OF BUGS MAY APPEAR**

# Avaliable options:
## List 
list folders [-a, -r, -pc]
list contacts [-v, --gal] (--gal not tested)
TODO: list emails (soon)

## Dump
dump folders [-d, -f, -t] (1-2 threads is fine)
### TODO: dump contacts (simply write to .txt?)
### TODO: dump emails (by passing ids list?) 
### TODO: dump attachments

## Search
search emails [-f, --dump, -t, --field]
### TODO: search attachments
### TODO: fix --field subject search

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
1) Выкачивание папок и писем в файлы формата mbox
2) Нормальный и настраиваемый листинг папок
3) Многопоточность + красивый tqdm (для dump folder режима)
4) Нормальный и рабочий поиск по тексту письма с возможность дампа результатов в mbox (последние результаты в .txt)
5) Сделай autodiscover запрос в один клик без бурпа и т.п.
6) Оставь -p пустым чтобы не сохранять пароль в истории


# Usage

python3 pymailsniper.py -h
python3 pymailsniper.py dump -h
python3 pymailsniper.py list -h
python3 pymailsniper.py search -h
python3 pymailsniper.py autodiscover -h


