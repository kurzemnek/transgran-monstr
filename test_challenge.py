#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Челлендж детектора. Ломаем распознавание телефонов, имён и почт.

Две половины:
  ЛОВИТЬ   — то, что обязано опознаться как персональные данные;
  ПРОПУСКАТЬ — то, что формой похоже, но данными не является. Ложное
  срабатывание здесь дороже пропуска: гейт уронит нормальный файл, и человек
  начнёт выключать проверки.

Запуск: python test_challenge.py [-v]
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from anonymizer import (looks_like_phone, looks_like_email, looks_like_name,
                        has_pii, norm_phone, RE_SNILS, detect)

VERBOSE = '-v' in sys.argv
fails = []

# ── телефоны, которые обязаны ловиться ──────────────────────────────────────
PHONES_YES = [
    '+7 999 123-45-67', '+79991234567', '89991234567', '8 999 123 45 67',
    '8(999)123-45-67', '8 (999) 123-45-67', '+7(999)123-45-67',
    '8-999-123-45-67', '+7-999-123-45-67', '7 999 123 45 67', '79991234567',
    '9991234567', '999 123 45 67', '999-123-45-67',
    '+7.999.123.45.67', '8.999.123.45.67',                     # точки как разделитель
    '+7 (495) 123-45-67', '8 495 123 45 67', '84951234567',    # городской Москва
    '+7 812 123-45-67', '8 800 555 35 35', '88005553535',      # Питер и 8-800
    '+7 (3452) 12-34-56',                                      # четырёхзначный код города
    'тел. 89991234567', 'звонить на +7 999 123-45-67 после 18',
    'моб: 8-999-123-45-67, доп 8-916-000-11-22',
    '+380 67 123 45 67', '+49 151 12345678', '+1 415 555 2671',  # иностранные
    '123-45-67',                                                 # городской без кода
    '+7 999 1234567', '8 9991234567',
]
# ── то, что телефоном НЕ является ───────────────────────────────────────────
PHONES_NO = [
    '129000', '129000.00', '1290000,50', '250 000', '4 900',
    '2026-09-21', '21.09.2026', '2026-09-21T10:00:00+03:00', '21/09/2026',
    '12:30:45', '00:45', '90667581', '431087', '18446744073709551615',
    '4607123456789', 'ART-12345678', '7743013901', '771234567890',
    'utm_campaign=rsya_cold', 'RUB', '0', '', '   ', '1000000',
    '2 104', '662%', '1,48', '16 262', '229912',
]

# ── почты ───────────────────────────────────────────────────────────────────
EMAILS_YES = [
    'ivanov@mail.ru', 'IVANOV@MAIL.RU', 'ivan.petrov+crm@yandex.ru',
    'a@b.co', 'test_user-1@sub.domain.co.uk', 'почта@яндекс.рф',
    'пишите на ivanov@mail.ru срочно', 'ivanov@mail.ru, petrov@mail.ru',
    'i.ivanov@corp-mail.company.com',
]
EMAILS_NO = [
    '@vkurzemnek', 'ООО@Ромашка', 'price@2026', 'client @ mail',
    'yandex', 'utm_source=email', 'email', 'rsya_cold@', '@', 'a@b',
]

# ── имена ───────────────────────────────────────────────────────────────────
NAMES_YES_STRONG = [
    'Иванов Иван Петрович', 'Мария Сергеевна', 'Петрова А.А.',
    'А.А. Петрова', 'Иванов И.И.', 'Нурсултан Абишевич',
    'позвонил Сидоров Пётр Ильич',
]
NAMES_YES_HUMAN = [          # ловим только в человеческих колонках
    'Иванов Иван', 'Анна-Мария Петрова', 'иванов иван', 'ИВАНОВ ИВАН',
    'Ivanov Ivan', 'John Smith', 'Пётр Кузнецов',
]
NAMES_NO = [                 # не имя даже в человеческой колонке
    'ООО Ромашка', 'Москва', '129000', 'yandex', 'В работе', 'Оплачено',
    'RUB', '2026-09-21', 'Воронка продаж',
]
NAMES_NO_NEUTRAL = [         # не должно ловиться в обычных колонках
    'Нижний Новгород', 'Санкт-Петербург', 'Ростов-на-Дону', 'Яндекс Директ',
    'Google Ads', 'Black Friday', 'Новый Год', 'Первый Экран',
    'Сделка Оплачена', 'Заявка Принята', 'Холодный Трафик',
]

SNILS_YES = ['123-456-789 01', '123-456-789-01']


TOTAL = [0]


def check(group, value, ok, extra=''):
    TOTAL[0] += 1
    mark = 'OK  ' if ok else 'ПРОВАЛ'
    if not ok:
        fails.append((group, value, extra))
    if VERBOSE or not ok:
        print(f'  {mark} [{group}] {value!r} {extra}')


print('\n── ТЕЛЕФОНЫ: обязаны ловиться ──')
for v in PHONES_YES:
    check('phone+', v, looks_like_phone(v))
print('\n── ТЕЛЕФОНЫ: ловиться не должны ──')
for v in PHONES_NO:
    check('phone-', v, not looks_like_phone(v))

print('\n── ПОЧТЫ: обязаны ловиться ──')
for v in EMAILS_YES:
    check('mail+', v, looks_like_email(v))
print('\n── ПОЧТЫ: ловиться не должны ──')
for v in EMAILS_NO:
    check('mail-', v, not looks_like_email(v))

print('\n── ИМЕНА: обязаны ловиться везде ──')
for v in NAMES_YES_STRONG:
    check('name+', v, looks_like_name(v, weak=False))
print('\n── ИМЕНА: ловятся в человеческих колонках ──')
for v in NAMES_YES_HUMAN:
    check('nameH+', v, looks_like_name(v, weak=True))
print('\n── ИМЕНА: не имя нигде ──')
for v in NAMES_NO:
    check('name-', v, not looks_like_name(v, weak=True))
print('\n── ИМЕНА: не имя в обычной колонке ──')
for v in NAMES_NO_NEUTRAL:
    check('nameN-', v, not looks_like_name(v, weak=False))

print('\n── СНИЛС ──')
for v in SNILS_YES:
    check('snils+', v, bool(RE_SNILS.search(v)))

# ── нормализация: один номер в разных написаниях = одна строка ──────────────
print('\n── НОРМАЛИЗАЦИЯ ──')
GROUPS = [
    ['+7 999 123-45-67', '89991234567', '79991234567', '9991234567',
     '8 (999) 123-45-67', '+7.999.123.45.67', '8-999-123-45-67'],
    ['+7 495 123-45-67', '84951234567', '4951234567'],
    ['8 800 555 35 35', '88005553535', '+7 800 555 35 35'],
]
for g in GROUPS:
    keys = {norm_phone(v) for v in g}
    check('norm', g[0], len(keys) == 1, f'-> {keys}')
DIFFERENT = ['+79991234567', '+79161112233', '+74951234567']
check('norm≠', 'разные номера', len({norm_phone(v) for v in DIFFERENT}) == 3)
check('norm-мусор', 'короткое', norm_phone('12345') == '')

# ── колонки целиком ─────────────────────────────────────────────────────────
print('\n── КОЛОНКИ ──')
header = ['ID', 'Телефон', 'Почта', 'Город', 'Стадия', 'Сумма', 'UTM Source',
          'Клиент', 'Комментарий', 'Дата']
rows = [
    ['1', '+7 999 123-45-67', 'a@mail.ru', 'Нижний Новгород', 'Оплачено', '129000', 'yandex',
     'Иванов Иван', 'перезвонить', '2026-09-21'],
    ['2', '8 (495) 111-22-33', 'b@mail.ru', 'Санкт-Петербург', 'В работе', '49000', 'google',
     'Петров Пётр', 'ок', '2026-09-22'],
    ['3', '89161112233', 'c@mail.ru', 'Ростов-на-Дону', 'Отказ', '0', 'yandex',
     'Сидорова Анна', 'звонить на 8 999 000-11-22', '2026-09-23'],
]
plan = {n: a for n, a, _ in detect(header, rows)}
for col, want in (('ID', 'keep'), ('Телефон', 'hash'), ('Почта', 'hash'),
                  ('Город', 'keep'), ('Стадия', 'keep'), ('Сумма', 'keep'),
                  ('UTM Source', 'keep'), ('Клиент', 'drop'),
                  ('Комментарий', 'drop'), ('Дата', 'keep')):
    check('col', col, plan.get(col) == want, f'решено {plan.get(col)}, ждали {want}')


# ── РАУНД 2: то, что ломает распознавание в реальных выгрузках ──────────────
print('\n── РАУНД 2: экзотика форматов ──')
ROUND2_PHONE_YES = [
    '+7\u00a0999\u00a0123\u00a045\u00a067',      # неразрывные пробелы из Word
    '+7 999 123\u201145\u201167',                  # неразрывный дефис
    '8\u2014999\u2014123\u201445\u201467',        # длинное тире
    "'+79991234567",                                # апостроф-префикс из Excel
    '79991234567.0',                                # число с плавающей точкой
    '7.9991234567E+10',                             # научная нотация Excel
    '+7 (999) 123-45-67 доб. 1234',
    'ИП Иванов, тел 8-999-123-45-67',
]
ROUND2_PHONE_NO = [
    '192.168.1.1', '1.2.3.4', '55.7558, 37.6173', 'Д-8-999-123', '№ 8 999',
    '8-999', '8 999', '2026', '10 223 129', '1 290 000', '№12345678',
]
ROUND2_EMAIL_YES = [
    'ivanov@mail.ru;petrov@mail.ru', '<ivanov@mail.ru>', 'mailto:ivanov@mail.ru',
    'Иванов Иван <ivanov@mail.ru>',
]
ROUND2_NAME_STRONG_YES = [
    'Иванов-Петров Иван Сергеевич', 'Рустам Ахмед оглы Мамедов',
    'ИП Иванов И.И.', 'директор Петрова М.С.',
]
CARD_YES = ['4276 1600 1234 5675', '4111111111111111', '5536-9137-1234-5673',
            '2202 2003 1234 5679']          # валидны по Луну
CARD_NO = ['4607123456789', '4276160012345678', '18446744073709551615',
           '1234 5678 9012 3456', '10 223 129', '2026-09-21']

for v in ROUND2_PHONE_YES:
    check('r2phone+', v, looks_like_phone(v))
for v in ROUND2_PHONE_NO:
    check('r2phone-', v, not looks_like_phone(v))
for v in ROUND2_EMAIL_YES:
    check('r2mail+', v, looks_like_email(v))
for v in ROUND2_NAME_STRONG_YES:
    check('r2name+', v, looks_like_name(v, weak=False))
for v in CARD_YES:
    check('card+', v, has_pii(v) == 'карта', f'-> {has_pii(v)}')
for v in CARD_NO:
    check('card-', v, has_pii(v) != 'карта', f'-> {has_pii(v)}')

print('\n── РАУНД 2: нормализация экзотики ──')
R2_GROUPS = [
    ['+7 999 123-45-67', "'+79991234567", '79991234567.0', '7.9991234567E+10',
     '+7\u00a0999\u00a0123\u00a045\u00a067'],
]
for g in R2_GROUPS:
    keys = {norm_phone(v) for v in g}
    check('r2norm', g[0], len(keys) == 1, f'-> {keys}')

print('\n── РАУНД 2: разделители файла ──')
import tempfile
from anonymizer import read_table
tmp2 = tempfile.mkdtemp()
for name, sep in (('tab.csv', '\t'), ('semi.csv', ';'), ('comma.csv', ',')):
    p2 = os.path.join(tmp2, name)
    open(p2, 'w', encoding='utf-8').write(
        sep.join(['ID', 'Телефон', 'Сумма']) + '\n' +
        sep.join(['1', '+79991234567', '100']) + '\n')
    try:
        h2, r2 = read_table(p2)
        check('sep', name, h2 == ['ID', 'Телефон', 'Сумма'] and len(r2) == 1, f'-> {h2}')
    except Exception as e:
        check('sep', name, False, str(e))

print('\n' + '─' * 60)
if fails:
    print(f'ПРОВАЛОВ: {len(fails)}')
    for g, v, e in fails:
        print(f'  [{g}] {v!r} {e}')
else:
    print('ВСЁ СОШЛОСЬ, проверок: %d' % TOTAL[0])
sys.exit(1 if fails else 0)
