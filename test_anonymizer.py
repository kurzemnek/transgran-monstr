#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Проверка обезличивателя. Запуск: python test_anonymizer.py"""
import os, sys, tempfile, zipfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from anonymizer import read_table, detect, process, gate, get_salt, run_file

FAIL = []
def check(name, ok, detail=''):
    print(('  OK   ' if ok else '  ПРОВАЛ ') + name + (f' — {detail}' if detail else ''))
    if not ok: FAIL.append(name)

tmp = tempfile.mkdtemp()
salt = get_salt()

# ── 1. склейка выживает через разные форматы ────────────────────────────────
p = os.path.join(tmp, 'a.csv')
open(p, 'w', encoding='utf-8').write(
    'ID;Телефон;Почта;Сумма\n'
    '1;+7 999 123-45-67;ivanov@mail.ru;100\n'
    '2;8 (999) 123-45-67;Ivanov@Mail.RU;200\n'
    '3;79991234567;ivanov@mail.ru;300\n'
    '4;+79161112233;other@mail.ru;400\n')
h, r = read_table(p); plan = detect(h, r); oh, orr = process(h, r, plan, salt)
print('\nТест 1 — склейка через форматы')
check('три написания дают один хеш', orr[0][1] == orr[1][1] == orr[2][1])
check('разные номера дают разные хеши', orr[0][1] != orr[3][1])
check('почта нечувствительна к регистру', orr[0][2] == orr[1][2])
check('сумма не тронута', [x[3] for x in orr] == ['100', '200', '300', '400'])

# ── 2. решения по колонкам ──────────────────────────────────────────────────
p = os.path.join(tmp, 'b.csv')
open(p, 'w', encoding='utf-8').write(
    'ID;Название;Телефон;Сумма;UTM Source;Комментарий;Ответственный;Воронка\n'
    '1;Сделка Иванов Иван;+79991234567;1000;yandex;звонить после 18 на 8 912 345-67-89;Петрова Анна;2\n'
    '2;Сделка Сидоров Пётр;+79992223344;2000;google;ок;Петрова Анна;2\n'
    '3;Сделка Кузнецов Олег;+79993334455;3000;yandex;;Смирнов Пётр;1\n')
h, r = read_table(p); plan = detect(h, r)
acts = {n: a for n, a, _ in plan}
print('\nТест 2 — решения по колонкам')
check('телефон хешируется', acts['Телефон'] == 'hash')
check('ФИО выбрасывается', acts['Контакт' if 'Контакт' in acts else 'Ответственный'] == 'drop')
check('название сделки с ФИО выбрасывается', acts['Название'] == 'drop')
check('комментарий с телефоном выбрасывается', acts['Комментарий'] == 'drop')
check('деньги остаются', acts['Сумма'] == 'keep')
check('UTM остаётся', acts['UTM Source'] == 'keep')
check('воронка остаётся', acts['Воронка'] == 'keep')

# ── 3. гейт ловит то, что просочилось мимо выборки ──────────────────────────
p = os.path.join(tmp, 'c.csv')
lines = ['ID;Детали']
for i in range(1, 760):
    lines.append(f'{i};обычный текст')
lines.append('760;позвонить на 8 999 111-22-33')
open(p, 'w', encoding='utf-8').write('\n'.join(lines) + '\n')
h, r = read_table(p); plan = detect(h, r)   # выборка 600 строк телефон не видит
oh, orr = process(h, r, plan, salt)
bad = gate(oh, orr)
print('\nТест 3 — гейт на хвосте файла')
check('колонка проскочила мимо выборки', {n: a for n, a, _ in plan}['Детали'] == 'keep')
check('гейт поймал на выходе', bad and bad[0][0] == 'Детали' and bad[0][1] == 'телефон', str(bad))
out, _, bad2, _info = run_file(p, log=lambda *_: None)
check('файл при провале не сохранён', out is None and not os.path.exists(p.replace('.csv', '_обезличено.csv')))
check('в отчёте гейта нет значений', all('999' not in str(x) for x in bad), str(bad))

# ── 4. чтение xlsx ──────────────────────────────────────────────────────────
NS = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'
p = os.path.join(tmp, 'd.xlsx')
with zipfile.ZipFile(p, 'w') as z:
    z.writestr('[Content_Types].xml',
        '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="xml" ContentType="application/xml"/></Types>')
    z.writestr('xl/sharedStrings.xml',
        f'<?xml version="1.0"?><sst xmlns="{NS}" count="5" uniqueCount="5">'
        '<si><t>ID</t></si><si><t>Телефон</t></si><si><t>Сумма</t></si>'
        '<si><t>+7 999 123-45-67</t></si><si><t>Иванов Иван</t></si></sst>')
    z.writestr('xl/worksheets/sheet1.xml',
        f'<?xml version="1.0"?><worksheet xmlns="{NS}"><sheetData>'
        '<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c><c r="C1" t="s"><v>2</v></c></row>'
        '<row r="2"><c r="A2"><v>1</v></c><c r="B2" t="s"><v>3</v></c><c r="C2"><v>5000</v></c></row>'
        '</sheetData></worksheet>')
h, r = read_table(p)
print('\nТест 4 — чтение xlsx без сторонних библиотек')
check('заголовки прочитаны', h == ['ID', 'Телефон', 'Сумма'], str(h))
check('строка прочитана', r and r[0][2] == '5000', str(r))
plan = detect(h, r)
check('телефон из xlsx распознан', {n: a for n, a, _ in plan}['Телефон'] == 'hash')


# ── 5. две выгрузки в разные дни дают одинаковые хеши ───────────────────────
print('\nТест 5 — неделя сегодня, полгода завтра')
import csv as _csv
from anonymizer import run_file, salt_fingerprint, get_salt

week = os.path.join(tmp, 'week.csv')
open(week, 'w', encoding='utf-8').write(
    'ID;Телефон;Сумма\n'
    '1;+7 999 123-45-67;100\n'
    '2;8 (916) 111-22-33;200\n')
half = os.path.join(tmp, 'halfyear.csv')
open(half, 'w', encoding='utf-8').write(
    'ID;Телефон;Сумма\n'
    '1;89991234567;100\n'          # тот же человек, другое написание
    '2;+79161112233;200\n'
    '3;+7 495 000-11-22;300\n')

out1, _, _, info1 = run_file(week, log=lambda *_: None)
out2, _, _, info2 = run_file(half, log=lambda *_: None)

def keys_of(path):
    with open(path, encoding='utf-8-sig') as f:
        rows = list(_csv.reader(f, delimiter=';'))
    idx = [i for i, h in enumerate(rows[0]) if h.endswith('(хеш)')][0]
    return [r[idx] for r in rows[1:]]

k1, k2 = keys_of(out1), keys_of(out2)
check('первый человек склеился между выгрузками', k1[0] == k2[0], f'{k1[0][:12]} / {k2[0][:12]}')
check('второй человек склеился', k1[1] == k2[1])
check('новый человек получил свой ключ', k2[2] not in k1)
check('отпечаток ключа совпадает', info1['fingerprint'] == info2['fingerprint'], info1['fingerprint'])
check('уникальных во второй выгрузке 3', info2['keys'][0]['unique'] == 3, str(info2['keys']))
check('уникальных в первой выгрузке 2', info1['keys'][0]['unique'] == 2)

# ── 6. счёт уникальных контактов ────────────────────────────────────────────
print('\nТест 6 — счёт уникальных контактов')
dup = os.path.join(tmp, 'dup.csv')
open(dup, 'w', encoding='utf-8').write(
    'ID;Телефон;Сумма\n'
    '1;+7 999 123-45-67;100\n'
    '2;89991234567;200\n'          # тот же человек
    '3;79991234567;300\n'          # и снова он
    '4;+7 916 111-22-33;400\n'
    '5;;500\n')                     # без телефона
out3, _, _, info3 = run_file(dup, log=lambda *_: None)
k = info3['keys'][0]
check('строк 5', info3['rows'] == 5, str(info3['rows']))
check('уникальных контактов 2', k['unique'] == 2, str(k))
check('заполнено 4', k['filled'] == 4, str(k))
check('без ключа 1', k['empty'] == 1, str(k))

print('\n── причина решения честная ──')
plan = dict((n, w) for n, a, w in detect(
    ['ID', 'Комментарий', 'Клиент', 'Детали', 'Сумма'],
    [['1', 'перезвонить позже', 'Иванов Иван', 'звонил +7 999 123-45-67', '1000'],
     ['2', 'отправил счет', 'Петров Пётр', 'ок', '2000'],
     ['3', 'не дозвонился', 'Сидорова Анна', 'ok', '3000']]))
check('комментарий не объявлен именем', plan['Комментарий'] == 'персональное поле по названию', plan['Комментарий'])
check('колонка с контактом внутри названа верно', plan['Детали'] == 'внутри текста встречаются контакты', plan['Детали'])

print('\nИТОГ: ' + ('всё сошлось' if not FAIL else 'провалено: ' + ', '.join(FAIL)))
sys.exit(1 if FAIL else 0)
