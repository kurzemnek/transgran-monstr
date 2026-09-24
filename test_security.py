#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Проверки безопасности. Каждая закрывает найденную и исправленную дыру.

  python test_security.py
"""
import csv
import os
import sys
import tempfile
import time
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import anonymizer as A

NS = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'
FAIL = []
tmp = tempfile.mkdtemp()


def check(name, ok, detail=''):
    print(('  OK   ' if ok else '  ПРОВАЛ ') + name + (f' — {detail}' if detail else ''))
    if not ok:
        FAIL.append(name)


def sheet(one_cell_shared=True):
    return ('<?xml version="1.0"?><worksheet xmlns="%s"><sheetData>'
            '<row r="1"><c r="A1" t="s"><v>0</v></c></row></sheetData></worksheet>' % NS)


print('\n── формулы в выходном файле ──')
p = os.path.join(tmp, 'inj.csv')
open(p, 'w', encoding='utf-8').write(
    'ID;Статус;Дельта\n1;=1+1;-5\n2;=HYPERLINK("http://evil");-12.5\n'
    '3;@SUM(A1:A9);+7\n4;-2+3;-0,5\n5;\tтаб;3\n')
out, _, _, _ = A.run_file(p, log=lambda *_: None)
rows = list(csv.reader(open(out, encoding='utf-8-sig'), delimiter=';'))
si, di = rows[0].index('Статус'), rows[0].index('Дельта')
check('формулы обезврежены', not [r for r in rows[1:] if r[si] and r[si][0] in '=+@\t\r'],
      str([r[si] for r in rows[1:]])[:60])
check('числа не испорчены', all(A.RE_NUMERIC.match(r[di]) for r in rows[1:]),
      str([r[di] for r in rows[1:]]))

print('\n── архив, который раздувается ──')
big = os.path.join(tmp, 'huge.xlsx')
with zipfile.ZipFile(big, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    z.writestr('xl/sharedStrings.xml', '<?xml version="1.0"?><sst xmlns="%s">%s</sst>'
               % (NS, ('<si><t>' + 'A' * 1000 + '</t></si>') * 80000))
    z.writestr('xl/worksheets/sheet1.xml', sheet())
ratio = os.path.getsize(big)
try:
    A.read_table(big)
    check('раздувание отклонено', False, 'файл принят')
except ValueError as e:
    check('раздувание отклонено', True, '%.0f КБ на диске' % (ratio / 1024))

print('\n── объявления сущностей ──')
ent = os.path.join(tmp, 'ent.xlsx')
with zipfile.ZipFile(ent, 'w') as z:
    z.writestr('xl/sharedStrings.xml',
               '<?xml version="1.0"?><!DOCTYPE t [<!ENTITY a "AAAA"><!ENTITY b "&a;&a;&a;">]>'
               '<sst xmlns="%s"><si><t>&b;</t></si></sst>' % NS)
    z.writestr('xl/worksheets/sheet1.xml', sheet())
try:
    A.read_table(ent)
    check('сущности отклонены', False, 'файл принят')
except ValueError:
    check('сущности отклонены', True)

print('\n── ключ хеширования ──')
A.save_salt(A.get_salt())
if A.IS_WIN:
    check('права проверяются только на Unix', True, 'пропущено')
else:
    check('ключ закрыт от чужих', os.stat(A.salt_path()).st_mode & 0o777 == 0o600)
    check('папка ключа закрыта', os.stat(A.salt_dir()).st_mode & 0o777 == 0o700)

print('\n── источник обновления ──')
CASES = (
    ('https://raw.githubusercontent.com/kurzemnek/transgran-monstr/main/latest.json', True),
    ('https://github.com/kurzemnek/transgran-monstr/releases/latest/download/x.exe', True),
    ('https://kurzemnek.ru/monstr/latest.json', True),
    ('http://raw.githubusercontent.com/x', False),
    ('https://evil.com/x.exe', False),
    ('https://githubusercontent.com.evil.com/x', False),
    ('https://github.com.evil.ru/x', False),
    ('file:///etc/passwd', False),
    ('', False),
)
for url, want in CASES:
    check('адрес: ' + (url[:52] or 'пусто'), A.trusted_url(url) == want)
try:
    A.download_update({'url': 'https://github.com/a/b/c.exe', 'sha256': ''})
    check('без контрольной суммы не качает', False)
except ValueError:
    check('без контрольной суммы не качает', True)

print('\n── отчёт о сбое не выносит данные ──')
def _crash_for(msg):
    try:
        raise ValueError(msg)
    except ValueError as e:
        return A.crash_text(type(e), e, e.__traceback__)

r = _crash_for('ячейка: +7 999 123-45-67')
check('телефон в отчёт не попал', '999' not in r and 'скрыто' in r)
r = _crash_for('строка: ivanov@mail.ru не разобрана')
check('почта в отчёт не попала', 'ivanov' not in r)
r = _crash_for(r'нет файла I:\база Иванов.csv')
check('путь с пробелом не попал в отчёт', 'база' not in r and 'Иванов' not in r and 'скрыто' in r)
r = _crash_for('нет файла I:' + chr(92) + 'export.csv')
check('путь без пробела тоже скрыт', 'export' not in r and 'скрыто' in r)
r = _crash_for('нет файла /home/pulsius/secret.csv')
check('домашний каталог скрыт', 'pulsius' not in r and 'secret' not in r)
r = _crash_for('колонок 8, строк 400')
check('безобидное сообщение остаётся', 'колонок 8' in r)
check('версия и система названы', A.VERSION in r and 'система:' in r)
u = A.issue_url('тело обращения', 'Сбой')
check('обращение открывается на github', u.startswith('https://github.com/kurzemnek/transgran-monstr/issues/new?'))
check('текст уезжает в параметрах ссылки', 'body=' in u and 'title=' in u)

print('\n── пропавший файл объясняется словами ──')
import subprocess as _sp
here = os.path.dirname(os.path.abspath(__file__))
r = _sp.run([sys.executable, os.path.join(here, 'anonymizer.py'),
             os.path.join(tmp, 'нет-такого.csv'), '--cli'],
            capture_output=True, text=True, timeout=60)
check('код возврата 2', r.returncode == 2, str(r.returncode))
check('сказано, что файл не найден', 'файл не найден' in r.stdout, r.stdout.strip()[:60])
check('трейсбека нет', 'Traceback' not in (r.stdout + r.stderr))

print('\n── ключ у каждой машины свой ──')
import stat as _stat
was_dir, was_here = A.salt_dir, A.HERE
d1, d2 = tempfile.mkdtemp(), tempfile.mkdtemp()
try:
    A.HERE = tempfile.mkdtemp()            # чтобы не подхватился ключ из папки программы
    A.salt_dir = lambda: d1
    k1 = A.get_salt()
    A.salt_dir = lambda: d2
    k2 = A.get_salt()
    check('ключ длиной 64 символа', len(k1) == 64, str(len(k1)))
    check('на другой машине ключ другой', k1 != k2)
    A.salt_dir = lambda: d1
    check('на своей машине ключ не меняется', A.get_salt() == k1)
    check('один номер под двумя ключами даёт разные хеши',
          A.make_key(k1, '79991234567') != A.make_key(k2, '79991234567'))
    if not A.IS_WIN:
        mode = _stat.S_IMODE(os.stat(os.path.join(d1, 'salt.txt')).st_mode)
        check('ключ закрыт от чужих', mode == 0o600, oct(mode))
finally:
    A.salt_dir, A.HERE = was_dir, was_here

print('\n── обновление берёт файл своей системы ──')
win_only = {'version': '9.9', 'url': 'https://github.com/kurzemnek/transgran-monstr/releases/latest/download/TRANSGRAN-MONSTR.exe',
            'sha256': 'a' * 64}
both = dict(win_only, mac={'url': 'https://github.com/kurzemnek/transgran-monstr/releases/latest/download/TRANSGRAN-MONSTR-macos.zip',
                           'sha256': 'b' * 64})
was_win, was_mac = A.IS_WIN, A.IS_MAC
try:
    A.IS_WIN, A.IS_MAC = False, True
    check('на Mac манифест без раздела mac не обновляет', A.update_entry(win_only) is None)
    e = A.update_entry(both)
    check('на Mac берётся архив, а не exe', bool(e) and e['url'].endswith('-macos.zip'), e and e['url'].rsplit('/', 1)[-1])
    A.IS_WIN, A.IS_MAC = True, False
    e = A.update_entry(both)
    check('на Windows берётся exe', bool(e) and e['url'].endswith('.exe'), e and e['url'].rsplit('/', 1)[-1])
    A.IS_WIN, A.IS_MAC = False, False
    check('на Linux обновления нет', A.update_entry(both) is None)
finally:
    A.IS_WIN, A.IS_MAC = was_win, was_mac

print('\n── регулярки против длинных строк ──')
worst = 0
for s in ('+' + '1' * 300, '+7' + '(-)' * 100 + '9991234567', 'a' * 400 + '@' + 'b' * 400,
          'Иванов' + ' ' * 400 + 'Иван', '7' + '.' * 400 + '1', '8' + ' ' * 300 + '9991234567x'):
    t = time.time()
    A.has_pii(s, weak=True)
    worst = max(worst, time.time() - t)
check('разбор не залипает', worst < 0.2, '%.0f мс на худшей строке' % (worst * 1000))

print('\n' + '─' * 58)
print('ВСЁ СОШЛОСЬ' if not FAIL else 'ПРОВАЛЕНО: ' + ', '.join(FAIL))
sys.exit(1 if FAIL else 0)
