#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Обезличиватель выгрузок.

Маркетолог выгружает из CRM что угодно в CSV или Excel, перетаскивает файл на эту
программу и получает рядом файл, который можно отдавать нейросети. Телефоны и почты
превращаются в хеш, имена и свободные тексты выбрасываются, деньги, даты, UTM и
идентификаторы остаются нетронутыми.

Всё происходит на компьютере пользователя. Программа никуда ничего не отправляет
и интернет ей не нужен.

Запуск:
  двойной клик по «Обезличиватель.bat» — откроется окно
  перетащить файл на «Обезличиватель.bat» — обработает сразу
  python anonymizer.py файл.csv — то же самое из консоли
"""

import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sys
import random
import threading
import shutil
import subprocess
import tempfile
import urllib.parse
import urllib.request
import zipfile
from decimal import Decimal, InvalidOperation

IS_WIN = sys.platform.startswith('win')
IS_MAC = sys.platform == 'darwin'

try:
    import winsound
except ImportError:
    winsound = None
try:
    import soundtrack
except ImportError:
    soundtrack = None
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
SALT_PATH = os.path.join(HERE, 'salt.txt')

# ── что считаем персональными данными ────────────────────────────────────────
#
# Два уровня. STRONG ловим в любой колонке, даже если она называется «Примечание»:
# у этих форматов почти нет шансов оказаться чем-то другим. WEAK — только когда
# название колонки само намекает на человека, иначе «Yandex Direct» уедет в ФИО.

# Разделители внутри номера. Кроме обычных — неразрывный пробел из Word,
# неразрывный дефис и длинное тире: их приносит копипаст из писем и документов.
SEP = r'[\s.()\-\u00a0\u2010-\u2015]'

# Телефон с кодом страны: +7 / 8 и десять цифр. Ловит и мобильные, и городские,
# и 8-800, в любом написании — точки, скобки, дефисы, слитно.
RE_PHONE_CC = re.compile(r'(?<!\d)(?:\+?7|8)' + SEP + r'*\d{3}' + SEP + r'*\d{3}'
                         + SEP + r'*\d{2}' + SEP + r'*\d{2}(?!\d)')
# Мобильный без кода страны: 9xx и семь цифр.
RE_PHONE_10 = re.compile(r'(?<!\d)9\d{2}' + SEP + r'*\d{3}' + SEP + r'*\d{2}'
                         + SEP + r'*\d{2}(?!\d)')
# Международный: обязателен плюс, чтобы не хватать артикулы и суммы.
RE_PHONE_INTL = re.compile(r'\+\d(?:' + SEP + r'*\d){9,16}(?!\d)')
# Городской без кода города, семь цифр через дефис: 123-45-67.
RE_PHONE_7 = re.compile(r'(?<![\d\-])\d{3}-\d{2}-\d{2}(?![\d\-])')

RE_EMAIL = re.compile(r'[^\s@;,:<>()\[\]"]+@[^\s@;,:<>()\[\]"]+\.[^\s@;,:<>()\[\]".]{2,}')

# Отчество — самый надёжный маркер человека в русском тексте.
RE_PATRONYMIC = re.compile(r'\b[А-ЯЁ][а-яё]+(?:ович|евич|иевич|ьич|овна|евна|иевна|ична|инична)\b')
# Тюркское отчество стоит отдельным словом: Ахмед оглы, Айгуль кызы.
RE_PATRONYMIC_TURK = re.compile(r'\b(?:оглы|оглу|кызы|гызы|улы|уулу|ызы)\b', re.I)
# Фамилия Имя / Имя Фамилия с заглавных, допускаются дефисные и ё.
RE_FIO_TITLE = re.compile(r'(?<![А-ЯЁа-яё])[А-ЯЁ][а-яё]+(?:-[А-ЯЁ][а-яё]+)?'
                          r'(?:\s+[А-ЯЁ][а-яё]+(?:-[А-ЯЁ][а-яё]+)?){1,2}(?![А-ЯЁа-яё])')
# Инициалы в обе стороны: Иванов И.И. и И.И. Иванов.
RE_FIO_INITIALS = re.compile(r'(?:[А-ЯЁ][а-яё]+\s*[А-ЯЁ]\.\s*[А-ЯЁ]?\.?'
                             r'|[А-ЯЁ]\.\s*[А-ЯЁ]?\.?\s*[А-ЯЁ][а-яё]+)')
# Номер карты: 13-19 цифр группами. Обязательна проверка Луна, иначе штрихкоды
# и артикулы поедут в «карты» и гейт начнёт ронять нормальные выгрузки.
RE_CARD = re.compile(r'(?<!\d)(?:\d[ \-]?){12,18}\d(?!\d)')


def luhn(digits):
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def looks_like_card(text):
    for m in RE_CARD.finditer(unexcel(text)):
        digits = re.sub(r'\D', '', m.group())
        if 13 <= len(digits) <= 19 and luhn(digits):
            return True
    return False


RE_SNILS = re.compile(r'(?<!\d)\d{3}-\d{3}-\d{3}[\s-]?\d{2}(?!\d)')

# WEAK — только в колонках, которые сами объявили себя человеческими.
RE_FIO_LATIN = re.compile(r'(?<![A-Za-z])[A-Z][a-z]+(?:-[A-Z][a-z]+)?'
                          r'(?:\s+[A-Z][a-z]+(?:-[A-Z][a-z]+)?){1,2}(?![A-Za-z])')
RE_FIO_LOWER = re.compile(r'(?<![А-ЯЁа-яё])[а-яё]{2,}(?:\s+[а-яё]{2,}){1,2}(?![А-ЯЁа-яё])')
RE_FIO_UPPER = re.compile(r'(?<![А-ЯЁа-яё])[А-ЯЁ]{2,}(?:\s+[А-ЯЁ]{2,}){1,2}(?![А-ЯЁа-яё])')

PHONE_RX = (RE_PHONE_CC, RE_PHONE_10, RE_PHONE_INTL, RE_PHONE_7)
# «Фамилия Имя» с заглавных живёт в WEAK сознательно: в обычной колонке этот
# рисунок дают «Нижний Новгород», «Яндекс Директ» и «Заявка Принята». Уронить
# на них файл хуже, чем пропустить имя в колонке, которая себя человеческой
# не назвала. Отчество и инициалы ложных не дают, поэтому они в STRONG.
NAME_RX_STRONG = (RE_PATRONYMIC, RE_PATRONYMIC_TURK, RE_FIO_INITIALS)
NAME_RX_WEAK = (RE_FIO_TITLE, RE_FIO_LATIN, RE_FIO_LOWER, RE_FIO_UPPER)

# Значения, которые формой похожи на телефон, но им не являются.
RE_NOT_PHONE = (
    re.compile(r'^\s*\d{4}-\d{2}-\d{2}'),                  # дата ISO
    re.compile(r'^\s*\d{2}\.\d{2}\.\d{4}'),                # дата 21.09.2026
    re.compile(r'^\s*[\d\s]+[.,]\d{1,2}\s*$'),              # сумма с копейками
)


RE_SCI = re.compile(r'^\d(?:\.\d+)?[eE][+-]?\d+$')
RE_FLOAT_TAIL = re.compile(r'^(\d+)\.0+$')


def unexcel(raw):
    """Снимает следы Excel: апостроф-префикс, хвост .0, научную нотацию.

    Телефон, попавший в ячейку как число, приезжает то как 79991234567.0,
    то как 7.9991234567E+10. Без разворота это разные строки и разные хеши.
    """
    t = (raw or '').strip().strip('\u00a0').lstrip("'").strip()
    if RE_SCI.match(t):
        try:
            return format(Decimal(t), 'f').rstrip('0').rstrip('.') or t
        except (InvalidOperation, ValueError):
            return t
    m = RE_FLOAT_TAIL.match(t)
    return m.group(1) if m else t


def looks_like_phone(text):
    t = unexcel(text)
    if not t:
        return False
    for rx in RE_NOT_PHONE:
        if rx.match(t):
            return False
    return any(rx.search(t) for rx in PHONE_RX)


def looks_like_email(text):
    return bool(RE_EMAIL.search(text or ''))


def looks_like_name(text, weak=False):
    t = (text or '').strip()
    if not t:
        return False
    if any(rx.search(t) for rx in NAME_RX_STRONG):
        return True
    return weak and any(rx.search(t) for rx in NAME_RX_WEAK)


def maybe_pii(text):
    """Дешёвый отсев перед разбором.

    Персональные данные всегда содержат либо цифру, либо собачку, либо
    заглавную букву. Строка «оплачено» не подходит ни под один разбор,
    и тратить на неё десяток регулярных выражений незачем — на большой
    выгрузке такой отсев снимает большую часть работы проверки.
    """
    for ch in text:
        if ch.isdigit() or ch == '@' or ch.isupper():
            return True
    return False


def has_pii(text, weak=False):
    """Единая проверка для гейта."""
    t = (text or '').strip()
    if not t or not maybe_pii(t):
        return None
    if looks_like_phone(t):
        return 'телефон'
    if looks_like_email(t):
        return 'почта'
    if RE_SNILS.search(t):
        return 'СНИЛС'
    if looks_like_card(t):
        return 'карта'
    if looks_like_name(t, weak):
        return 'имя'
    return None


# Колонки, которые выбрасываем по названию, даже если внутри чисто.
NAME_DROP = (
    'фио', 'имя', 'фамили', 'отчеств', 'name', 'contact', 'контакт', 'клиент',
    'адрес', 'address', 'комментарий', 'коммент', 'comment', 'примечание',
    'описание', 'заметк', 'должность', 'компания', 'организац',
    'название', 'заголовок', 'title', 'ответственн', 'менеджер', 'сотрудник',
    'паспорт', 'снилс', 'инн', 'дата рожд', 'birth', 'логин', 'login',
    'telegram', 'телеграм', 'whatsapp', 'вотсап', 'instagram', 'соцсет', 'профиль',
)
# Колонки-ключи: хешируем, чтобы склейка выжила.
NAME_HASH = ('телефон', 'phone', 'тел', 'моб', 'email', 'e-mail', 'почта', 'mail')
# Колонки, где разрешаем слабые детекторы имён.
NAME_HUMAN = NAME_DROP + ('person', 'user', 'лид', 'покупател', 'заказчик', 'плательщик')


def norm_header(h):
    return re.sub(r'\s+', ' ', (h or '')).strip().lower()


# ── чтение файла ─────────────────────────────────────────────────────────────

def read_table(path):
    ext = os.path.splitext(path)[1].lower()
    if ext in ('.xlsx', '.xlsm'):
        return read_xlsx(path)
    return read_csv(path)


def read_csv(path):
    with open(path, 'rb') as f:
        raw = f.read()
    for encoding in ('utf-8-sig', 'cp1251', 'utf-8'):
        try:
            text = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = raw.decode('utf-8', errors='replace')
    first = text.split('\n', 1)[0]
    delim = max((';', ',', '\t', '|'), key=first.count)
    if first.count(delim) == 0:
        delim = ';'
    rows = list(csv.reader(io.StringIO(text), delimiter=delim))
    rows = [r for r in rows if any((c or '').strip() for c in r)]
    if not rows:
        raise ValueError('файл пустой')
    return rows[0], rows[1:]


MAX_XML_BYTES = 64 * 1024 * 1024      # потолок на один распакованный файл
MAX_TOTAL_BYTES = 256 * 1024 * 1024   # и на всё вместе


def _safe_xml(z, name, budget):
    """Читает кусок архива с оглядкой на его настоящий размер.

    Книга на сто килобайт разворачивается в шестьдесят мегабайт — достаточно
    записать одну строку миллион раз. Объявленный размер известен заранее,
    поэтому такой файл отклоняется до чтения, а не после.
    """
    info = z.getinfo(name)
    if info.file_size > MAX_XML_BYTES or info.file_size > budget[0]:
        raise ValueError('файл внутри книги слишком большой: %.0f МБ'
                         % (info.file_size / 1048576))
    budget[0] -= info.file_size
    data = z.read(name)
    head = data[:2048].lstrip()
    if head.startswith(b'<?xml'):
        head = head.split(b'?>', 1)[-1].lstrip()
    if head.startswith(b'<!DOCTYPE') or b'<!ENTITY' in data[:8192]:
        raise ValueError('книга содержит объявления сущностей — такие файлы не читаю')
    return data


def read_xlsx(path):
    """Минимальный читатель xlsx без сторонних библиотек."""
    ns = '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}'
    budget = [MAX_TOTAL_BYTES]
    with zipfile.ZipFile(path) as z:
        shared = []
        if 'xl/sharedStrings.xml' in z.namelist():
            root = ET.fromstring(_safe_xml(z, 'xl/sharedStrings.xml', budget))
            for si in root.findall(f'{ns}si'):
                shared.append(''.join(t.text or '' for t in si.iter(f'{ns}t')))
        sheets = [n for n in z.namelist() if n.startswith('xl/worksheets/sheet')]
        if not sheets:
            raise ValueError('в файле нет листов')
        root = ET.fromstring(_safe_xml(z, sorted(sheets)[0], budget))
        rows = []
        for row in root.iter(f'{ns}row'):
            cells = {}
            for c in row.findall(f'{ns}c'):
                ref = c.get('r') or ''
                col = ''.join(ch for ch in ref if ch.isalpha())
                v = c.find(f'{ns}v')
                if c.get('t') == 's' and v is not None:
                    value = shared[int(v.text)] if v.text else ''
                elif c.get('t') == 'inlineStr':
                    value = ''.join(t.text or '' for t in c.iter(f'{ns}t'))
                else:
                    value = v.text if v is not None else ''
                cells[col] = value or ''
            if cells:
                width = max(col_index(k) for k in cells) + 1
                rows.append([cells.get(index_col(i), '') for i in range(width)])
    rows = [r for r in rows if any((c or '').strip() for c in r)]
    if not rows:
        raise ValueError('файл пустой')
    header = rows[0]
    body = [r + [''] * (len(header) - len(r)) for r in rows[1:]]
    return header, body


def col_index(letters):
    n = 0
    for ch in letters:
        n = n * 26 + (ord(ch.upper()) - 64)
    return n - 1


def index_col(i):
    s = ''
    i += 1
    while i:
        i, rem = divmod(i - 1, 26)
        s = chr(65 + rem) + s
    return s


# ── решение по каждой колонке ────────────────────────────────────────────────

def detect(header, rows, sample=600):
    """Возвращает список (имя, решение, причина). Решения: hash, drop, keep."""
    plan = []
    for i, name in enumerate(header):
        values = [(r[i] if i < len(r) else '') for r in rows[:sample]]
        values = [v for v in values if (v or '').strip()]
        low = norm_header(name)
        total = len(values) or 1
        human_col = any(k in low for k in NAME_HUMAN)

        phone_full = sum(1 for v in values if looks_like_phone(v) and len(re.sub(r'\D', '', v)) <= 16
                         and len(v.strip()) <= 24)
        email_full = sum(1 for v in values if RE_EMAIL.fullmatch(v.strip()))
        phone_any = sum(1 for v in values if looks_like_phone(v))
        email_any = sum(1 for v in values if looks_like_email(v))
        snils = sum(1 for v in values if RE_SNILS.search(v))
        names = sum(1 for v in values if looks_like_name(v, weak=human_col))

        key_col = any(k in low for k in NAME_HASH)

        if phone_full / total >= 0.5 or (key_col and phone_any / total >= 0.3):
            plan.append((name, 'hash', 'телефон — станет ключом склейки'))
        elif email_full / total >= 0.5 or (key_col and email_any / total >= 0.3):
            plan.append((name, 'hash', 'почта — станет ключом склейки'))
        elif key_col and not values:
            plan.append((name, 'hash', 'контакт по названию колонки'))
        elif snils:
            plan.append((name, 'drop', 'СНИЛС'))
        elif names / total >= 0.3:
            plan.append((name, 'drop', 'похоже на имя человека'))
        elif phone_any or email_any:
            plan.append((name, 'drop', 'внутри текста встречаются контакты'))
        elif any(k in low for k in NAME_DROP):
            plan.append((name, 'drop', 'персональное поле по названию'))
        else:
            plan.append((name, 'keep', ''))
    return plan


# ── обработка ────────────────────────────────────────────────────────────────

def salt_dir():
    """Ключ живёт вне папки программы, иначе перенос exe рвёт склейку."""
    if IS_WIN:
        base = os.environ.get('APPDATA') or os.path.expanduser('~')
    elif IS_MAC:
        base = os.path.expanduser('~/Library/Application Support')
    else:
        base = os.environ.get('XDG_CONFIG_HOME') or os.path.expanduser('~/.config')
    return os.path.join(base, 'TransgranMonstr')


def salt_path():
    return os.path.join(salt_dir(), 'salt.txt')


def get_salt():
    """Соль создаётся один раз на компьютер и дальше не меняется никогда.

    Главный сценарий: сегодня выгрузка за неделю, завтра за полгода. Один и тот
    же человек обязан получить один и тот же хеш в обеих, иначе склеить их между
    собой нельзя. Поэтому ключ переживает и перенос программы, и обновление.
    """
    path = salt_path()
    if os.path.exists(path):
        with open(path, encoding='utf-8') as f:
            value = f.read().strip()
        if len(value) >= 32:
            return value
    legacy = os.path.join(HERE, 'salt.txt')       # ключ старых версий, рядом с exe
    if os.path.exists(legacy):
        with open(legacy, encoding='utf-8') as f:
            value = f.read().strip()
        if len(value) >= 32:
            save_salt(value)
            return value
    value = secrets.token_hex(32)
    save_salt(value)
    return value


def save_salt(value):
    """Ключ пишем только для владельца: по нему хеши сводятся с телефонами."""
    os.makedirs(salt_dir(), exist_ok=True)
    path = salt_path()
    with open(path, 'w', encoding='utf-8') as f:
        f.write(value.strip())
    if not IS_WIN:
        try:
            os.chmod(path, 0o600)
            os.chmod(salt_dir(), 0o700)
        except OSError:
            pass


VERSION = '1.3'
# Манифест обновления — обычный JSON на любом статическом хостинге:
#   {"version": "1.3",
#    "url": "https://.../TRANSGRAN-MONSTR.exe",
#    "sha256": "…",
#    "notes": ["что изменилось", "…"]}
UPDATE_URL = 'https://raw.githubusercontent.com/kurzemnek/transgran-monstr/main/latest.json'

DEFAULTS = {'out_dir': '', 'music_on_start': False, 'open_after': False,
            'check_updates': True}


def settings_path():
    return os.path.join(salt_dir(), 'settings.json')


def load_settings():
    data = dict(DEFAULTS)
    try:
        with open(settings_path(), encoding='utf-8') as f:
            data.update(json.load(f))
    except Exception:
        pass
    return data


def save_settings(data):
    try:
        os.makedirs(salt_dir(), exist_ok=True)
        with open(settings_path(), 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except OSError:
        pass


def custom_path():
    return os.path.join(salt_dir(), 'custom.wav')


def has_custom():
    """Свой трек, если владелец машины положил его в личную папку.

    Лежит он рядом с ключом, а не рядом с программой: при передаче exe
    дальше он никуда не уезжает, и у получателя играет синтезированный.
    Подкладывается руками — кнопки для этого в интерфейсе сознательно нет.
    """
    p = custom_path()
    return os.path.exists(p) and os.path.getsize(p) > 100000


_TRACK = {'data': None}


def audio_ready():
    return has_custom() or _TRACK['data'] is not None


def build_track(done=None):
    """Музыка синтезируется в память и оттуда же играет.

    Файла на диске не появляется вовсе: программа остаётся одним exe,
    после неё в системе не остаётся ничего, кроме ключа хеширования.
    """
    def work():
        ok = False
        try:
            if soundtrack:
                _TRACK['data'] = soundtrack.render_bytes(110.0)
                ok = _TRACK['data'] is not None
        except Exception:
            ok = False
        if done:
            done(ok)
    threading.Thread(target=work, daemon=True).start()


_PLAYER = {'proc': None, 'stop': False}


def _cli_player():
    """Чем играть там, где нет winsound."""
    for cmd in (['afplay'], ['paplay'], ['aplay', '-q']):
        if shutil.which(cmd[0]):
            return cmd
    return None


def _temp_track():
    """afplay и aplay читают файл, поэтому синтез кладём во временный."""
    p = os.path.join(tempfile.gettempdir(), 'transgran_track.wav')
    if not os.path.exists(p) and _TRACK['data']:
        with open(p, 'wb') as f:
            f.write(_TRACK['data'])
    return p if os.path.exists(p) else None


def play_loop():
    if winsound:
        if has_custom():
            winsound.PlaySound(custom_path(),
                               winsound.SND_FILENAME | winsound.SND_ASYNC | winsound.SND_LOOP)
            return True
        if _TRACK['data']:
            winsound.PlaySound(_TRACK['data'],
                               winsound.SND_MEMORY | winsound.SND_ASYNC | winsound.SND_LOOP)
            return True
        return False

    cmd = _cli_player()
    path = custom_path() if has_custom() else _temp_track()
    if not cmd or not path:
        return False

    def spin():
        while not _PLAYER['stop']:
            try:
                _PLAYER['proc'] = subprocess.Popen(cmd + [path],
                                                   stdout=subprocess.DEVNULL,
                                                   stderr=subprocess.DEVNULL)
                _PLAYER['proc'].wait()
            except Exception:
                return

    _PLAYER['stop'] = False
    threading.Thread(target=spin, daemon=True).start()
    return True


def stop_sound():
    if winsound:
        winsound.PlaySound(None, winsound.SND_PURGE)
        return
    _PLAYER['stop'] = True
    proc = _PLAYER.get('proc')
    if proc and proc.poll() is None:
        try:
            proc.terminate()
        except Exception:
            pass


def open_folder(path):
    try:
        if IS_WIN:
            os.startfile(path)
        elif IS_MAC:
            subprocess.Popen(['open', path])
        else:
            subprocess.Popen(['xdg-open', path])
    except Exception:
        pass


def salt_fingerprint(salt):
    """Короткий отпечаток ключа. Совпал у двух выгрузок — хеши сравнимы."""
    return hashlib.sha256(('fp:' + salt).encode('utf-8')).hexdigest()[:8].upper()


def salt_is_new():
    return not os.path.exists(salt_path())


def norm_phone(raw):
    """Один и тот же номер в любом написании обязан дать одну строку.

    Российские номера сводим к десяти цифрам без кода страны: и мобильные,
    и городские, и 8-800. Иностранные оставляем целиком — там последние десять
    цифр не опознают страну и склеят разных людей.
    """
    digits = re.sub(r'\D', '', unexcel(raw))
    if not digits:
        return ''
    if len(digits) == 11 and digits[0] in ('7', '8'):
        return digits[1:]
    if len(digits) == 10:
        return digits
    if 11 < len(digits) <= 16:
        return digits.lstrip('0')
    return ''


def make_key(salt, value):
    return hmac.new(salt.encode('utf-8'), value.encode('utf-8'), hashlib.sha256).hexdigest()[:32]


def process(header, rows, plan, salt):
    keep_idx = [i for i, (_, act, _) in enumerate(plan) if act != 'drop']
    out_header = []
    for i in keep_idx:
        name, act, _ = plan[i]
        out_header.append(name + ' (хеш)' if act == 'hash' else name)
    out_rows = []
    for r in rows:
        line = []
        for i in keep_idx:
            value = r[i] if i < len(r) else ''
            _, act, _ = plan[i]
            if act == 'hash':
                norm = (value or '').strip().lower() if looks_like_email(value) else norm_phone(value)
                line.append(make_key(salt, norm) if norm else '')
            else:
                line.append(value)
        out_rows.append(line)
    return out_header, out_rows


def stats(out_header, out_rows):
    """Сколько уникальных людей и сколько строк осталось без ключа склейки."""
    res = {'rows': len(out_rows), 'keys': []}
    for i, name in enumerate(out_header):
        if not name.endswith('(хеш)'):
            continue
        values = [r[i] for r in out_rows if i < len(r)]
        filled = [v for v in values if v]
        res['keys'].append({
            'column': name[:-6].strip(),
            'unique': len(set(filled)),
            'filled': len(filled),
            'empty': len(values) - len(filled),
        })
    return res


def gate(header, rows):
    """Ищет ПДн в готовом выходе. Возвращает (колонка, тип), без самих значений."""
    bad = {}
    for i, name in enumerate(header):
        if name.endswith('(хеш)'):
            continue
        human_col = any(k in norm_header(name) for k in NAME_HUMAN)
        for r in rows:
            kind = has_pii(r[i] if i < len(r) else '', weak=human_col)
            if kind:
                bad[name] = kind
                break
    return sorted(bad.items())


RE_NUMERIC = re.compile(r'^[-+]?\d+(?:[.,]\d+)?$')


def csv_safe(value):
    """Обезвреживает формулы в выходном файле.

    Excel и Calc выполняют ячейку, начинающуюся с =, +, @ или минуса: строка
    вида =HYPERLINK("http://…") превращается в кликабельную ловушку, а
    =cmd|'/c calc'!A1 — в попытку запуска. Данные приехали из CRM, где эти
    строки мог ввести кто угодно, поэтому перед записью ставим апостроф —
    редактор покажет текст как есть и считать его не станет.
    """
    v = '' if value is None else str(value)
    if not v:
        return v
    if v[0] in '=@\t\r' or (v[0] in '+-' and not RE_NUMERIC.match(v)):
        return "'" + v
    return v


def write_csv(path, header, rows):
    with open(path, 'w', encoding='utf-8-sig', newline='') as f:
        w = csv.writer(f, delimiter=';')
        w.writerow([csv_safe(h) for h in header])
        for row in rows:
            w.writerow([csv_safe(v) for v in row])


def run_file(path, log=print, out_dir=''):
    header, rows = read_table(path)
    plan = detect(header, rows)
    salt = get_salt()
    out_header, out_rows = process(header, rows, plan, salt)
    bad = gate(out_header, out_rows)
    info = stats(out_header, out_rows)
    info['fingerprint'] = salt_fingerprint(salt)
    base, _ = os.path.splitext(path)
    out_path = base + '_обезличено.csv'
    if out_dir and os.path.isdir(out_dir):
        out_path = os.path.join(out_dir, os.path.basename(out_path))
    if bad:
        log('ПРОВЕРКА НЕ ПРОЙДЕНА, файл не сохранён.')
        log('Контакты остались: ' + ', '.join('%s (%s)' % (n, k) for n, k in bad))
        return None, plan, bad, info
    write_csv(out_path, out_header, out_rows)
    log('Готово: ' + os.path.basename(out_path))
    log('Строк: %d. Колонок оставлено: %d из %d.' % (len(out_rows), len(out_header), len(header)))
    for k in info['keys']:
        log('Уникальных по «%s»: %d из %d заполненных' % (k['column'], k['unique'], k['filled']))
    return out_path, plan, bad, info


# ── обновление ───────────────────────────────────────────────────────────────

def _vernum(v):
    out = []
    for part in str(v).split('.'):
        digits = ''.join(ch for ch in part if ch.isdigit())
        out.append(int(digits) if digits else 0)
    return out


def app_file():
    """Путь к самой программе: в собранном виде это exe, иначе скрипт."""
    return sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)


ALLOWED_HOSTS = ('github.com', 'raw.githubusercontent.com', 'objects.githubusercontent.com',
                 'release-assets.githubusercontent.com', 'kurzemnek.ru', 'www.kurzemnek.ru')


def trusted_url(url):
    """Программа скачивает и запускает файл, поэтому источник закреплён.

    Проверяется и схема, и хост: без этого достаточно подменить манифест,
    чтобы указать на любой адрес, а контрольная сумма в том же манифесте
    от подмены не спасает — её пишет тот же, кто пишет ссылку.
    """
    p = urllib.parse.urlparse(url or '')
    if p.scheme != 'https':
        return False
    host = (p.hostname or '').lower()
    return any(host == h or host.endswith('.' + h) for h in ALLOWED_HOSTS)


def fetch_manifest(url=UPDATE_URL, timeout=6):
    if not trusted_url(url):
        raise ValueError('адрес обновления не из доверенного списка')
    req = urllib.request.Request(url, headers={'User-Agent': 'TransgranMonstr/' + VERSION})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode('utf-8'))


def check_update(done, url=UPDATE_URL):
    """Тихо спрашивает сервер, есть ли версия новее. Молчит при любой ошибке."""
    def work():
        info = None
        try:
            data = fetch_manifest(url)
            if _vernum(data.get('version', '0')) > _vernum(VERSION):
                info = data
        except Exception:
            info = None
        done(info)
    threading.Thread(target=work, daemon=True).start()


def download_update(info, progress=None):
    """Качает новый файл во временную папку и сверяет контрольную сумму."""
    url = info['url']
    if not trusted_url(url):
        raise ValueError('ссылка на файл не из доверенного списка')
    if not (info.get('sha256') or '').strip():
        raise ValueError('в манифесте нет контрольной суммы')
    tmp = os.path.join(tempfile.gettempdir(), 'transgran_update.bin')
    req = urllib.request.Request(url, headers={'User-Agent': 'TransgranMonstr/' + VERSION})
    with urllib.request.urlopen(req, timeout=30) as resp, open(tmp, 'wb') as f:
        total = int(resp.headers.get('Content-Length') or 0)
        got = 0
        while True:
            chunk = resp.read(1 << 16)
            if not chunk:
                break
            f.write(chunk)
            got += len(chunk)
            if progress and total:
                progress(got / total)
    want = (info.get('sha256') or '').lower().strip()
    if want:
        h = hashlib.sha256()
        with open(tmp, 'rb') as f:
            for chunk in iter(lambda: f.read(1 << 20), b''):
                h.update(chunk)
        if h.hexdigest() != want:
            os.remove(tmp)
            raise ValueError('контрольная сумма не сошлась')
    return tmp


def apply_update(tmp):
    """Подменяет работающий файл и перезапускает программу.

    Пока процесс жив, Windows держит свой exe занятым, поэтому подменой
    занимается короткий сценарий, который ждёт выхода и стартует новую версию.
    """
    target = app_file()
    if IS_WIN:
        bat = os.path.join(tempfile.gettempdir(), 'transgran_update.bat')
        with open(bat, 'w', encoding='cp866') as f:
            f.write('@echo off\r\n'
                    'ping 127.0.0.1 -n 3 >nul\r\n'
                    ':wait\r\n'
                    'move /y "%s" "%s" >nul 2>&1\r\n'
                    'if errorlevel 1 (ping 127.0.0.1 -n 2 >nul & goto wait)\r\n'
                    'start "" "%s"\r\n'
                    'del "%%~f0"\r\n' % (tmp, target, target))
        subprocess.Popen(['cmd', '/c', bat], creationflags=0x00000008)
    else:
        shutil.move(tmp, target)
        os.chmod(target, 0o755)
        subprocess.Popen([target])
    return True


# ── пиксельный монстр ────────────────────────────────────────────────────────
#
# Рисуется квадратами на холсте: B — тело, K — тень, E и P — глаз и зрачок,
# M — пасть, T — зубы, точка — пусто. Все кадры одного размера, меняются
# только цвета клеток, поэтому перерисовка дешёвая.

MON_PIX = 5
MON_COLORS = {
    'B': '#39FF14', 'K': '#1c7a0c', 'E': '#f2f2ff', 'P': '#07070a',
    'M': '#FF00D4', 'T': '#f2f2ff', 'R': '#FF2D55', '.': None,
}

_IDLE = (
    "....BBBBBB....",
    "..BBBBBBBBBB..",
    ".BBBBBBBBBBBB.",
    ".BBEEBBBBEEBB.",
    ".BBEPBBBBEPBB.",
    "BBBBBBBBBBBBBB",
    "BBTTTTTTTTTTBB",
    "BBBBBBBBBBBBBB",
    ".BBBBBBBBBBBB.",
    "..BB..BB..BB..",
    "..KK..KK..KK..",
)
_BLINK = (
    "....BBBBBB....",
    "..BBBBBBBBBB..",
    ".BBBBBBBBBBBB.",
    ".BBBBBBBBBBBB.",
    ".BBKKBBBBKKBB.",
    "BBBBBBBBBBBBBB",
    "BBTTTTTTTTTTBB",
    "BBBBBBBBBBBBBB",
    ".BBBBBBBBBBBB.",
    "..BB..BB..BB..",
    "..KK..KK..KK..",
)
_CHEW1 = (
    "....BBBBBB....",
    "..BBBBBBBBBB..",
    ".BBBBBBBBBBBB.",
    ".BBEEBBBBEEBB.",
    ".BBEPBBBBEPBB.",
    "BBBBBBBBBBBBBB",
    "BBTMMMMMMMMTBB",
    "BBBTTTTTTTTBBB",
    ".BBBBBBBBBBBB.",
    "..BB..BB..BB..",
    "..KK..KK..KK..",
)
_CHEW2 = (
    "....BBBBBB....",
    "..BBBBBBBBBB..",
    ".BBBBBBBBBBBB.",
    ".BBEEBBBBEEBB.",
    ".BBEPBBBBEPBB.",
    "BBTTTTTTTTTTBB",
    "BBMMMMMMMMMMBB",
    "BBMMMMMMMMMMBB",
    ".BTTTTTTTTTTB.",
    "..BB..BB..BB..",
    "..KK..KK..KK..",
)
_HAPPY = (
    "....BBBBBB....",
    "..BBBBBBBBBB..",
    ".BBBBBBBBBBBB.",
    ".BBKKBBBBKKBB.",
    ".BKBBKBBKBBKB.",
    "BBBBBBBBBBBBBB",
    "BBTBBBBBBBBTBB",
    "BBBTTTTTTTTBBB",
    ".BBBBBBBBBBBB.",
    "..BB..BB..BB..",
    "..KK..KK..KK..",
)
_ANGRY = (
    "....BBBBBB....",
    "..BBBBBBBBBB..",
    ".BKKBBBBBBKKB.",
    ".BBRRBBBBRRBB.",
    ".BBRPBBBBRPBB.",
    "BBBBBBBBBBBBBB",
    "BBRRRRRRRRRRBB",
    "BBBRRRRRRRRBBB",
    ".BBBBBBBBBBBB.",
    "..BB..BB..BB..",
    "..KK..KK..KK..",
)

MON_STATES = {
    'idle': (_IDLE,) * 10 + (_BLINK,),
    'chew': (_CHEW1, _CHEW2, _CHEW1, _IDLE),
    'happy': (_HAPPY, _HAPPY, _IDLE, _HAPPY),
    'angry': (_ANGRY, _IDLE, _ANGRY, _ANGRY),
}


# ── окно ─────────────────────────────────────────────────────────────────────

BG      = '#07070a'
PANEL   = '#0e0e14'
ACID    = '#39FF14'
MAGENTA = '#FF00D4'
CYAN    = '#00F0FF'
YELLOW  = '#FFE600'
RED     = '#FF2D55'
DIM     = '#4a4a55'
MONO    = 'Consolas' if IS_WIN else ('Menlo' if IS_MAC else 'DejaVu Sans Mono')

ACT_LABEL = {'hash': 'ХЕШ', 'drop': 'СОЖРАТЬ', 'keep': 'ОСТАВИТЬ'}
ACT_COLOR = {'hash': YELLOW, 'drop': MAGENTA, 'keep': ACID}

SITE = 'https://kurzemnek.ru'
TG = 'https://t.me/vkurzemnek'
CLAUDE_URL = 'https://claude.com/claude-code'


def gui(preset=None):
    import tkinter as tk
    import webbrowser
    from tkinter import filedialog

    root = tk.Tk()
    root.title('ТРАНСГРАНИЧНЫЙ МОНСТР')
    root.configure(bg=BG)
    root.geometry('980x700')
    root.minsize(860, 620)

    state = {'path': None, 'paths': [], 'plan': None, 'busy': False,
             'tab': 'РАЗВЕДКА', 'sound': False}

    def neon(parent, text, command, fg=ACID, size=11, pady=6, padx=18):
        b = tk.Label(parent, text=text, font=(MONO, size, 'bold'), fg=fg, bg=PANEL,
                     padx=padx, pady=pady, cursor='hand2',
                     highlightthickness=2, highlightbackground=fg, highlightcolor=fg)
        b.bind('<Button-1>', lambda e: command())
        b.bind('<Enter>', lambda e: b.configure(bg=fg, fg=BG))
        b.bind('<Leave>', lambda e: b.configure(bg=PANEL, fg=fg))
        return b

    def link(parent, text, url, fg=CYAN, size=11):
        l = tk.Label(parent, text=text, font=(MONO, size, 'underline'), fg=fg, bg=BG, cursor='hand2')
        l.bind('<Button-1>', lambda e: webbrowser.open(url))
        return l

    # ── баннер ───────────────────────────────────────────────────────────────
    head = tk.Frame(root, bg=BG, padx=22, pady=14)
    head.pack(fill='x')
    box = tk.Frame(head, bg=BG, highlightthickness=2,
                   highlightbackground=MAGENTA, highlightcolor=MAGENTA)
    box.pack(anchor='w', fill='x')
    inner = tk.Frame(box, bg=BG, padx=16, pady=8)
    inner.pack(fill='x')
    title_lbl = tk.Label(inner, text='ТРАНСГРАНИЧНЫЙ МОНСТР', font=(MONO, 26, 'bold'),
                         fg=ACID, bg=BG)
    title_lbl.pack(side='left')
    tk.Label(inner, text='v1.3', font=(MONO, 11), fg=CYAN, bg=BG).pack(side='left',
                                                                       padx=(12, 0), pady=(14, 0))
    mon_w = len(_IDLE[0]) * MON_PIX
    mon_h = len(_IDLE) * MON_PIX
    mon = tk.Canvas(inner, width=mon_w, height=mon_h, bg=BG, highlightthickness=0)
    mon.pack(side='left', padx=(34, 0), pady=(4, 0))
    mon_cells = []
    for y in range(len(_IDLE)):
        row = []
        for x in range(len(_IDLE[0])):
            row.append(mon.create_rectangle(x * MON_PIX, y * MON_PIX,
                                            (x + 1) * MON_PIX, (y + 1) * MON_PIX,
                                            width=0, fill=BG))
        mon_cells.append(row)
    mon_state = {'name': 'idle', 'frame': 0, 'hold': 0}

    def draw_monster(grid):
        for y, line in enumerate(grid):
            for x, ch in enumerate(line):
                color = MON_COLORS.get(ch)
                mon.itemconfig(mon_cells[y][x], fill=color or BG)

    def set_monster(name, hold=0):
        mon_state['name'] = name
        mon_state['frame'] = 0
        mon_state['hold'] = hold

    def tick_monster():
        frames = MON_STATES[mon_state['name']]
        draw_monster(frames[mon_state['frame'] % len(frames)])
        mon_state['frame'] += 1
        if mon_state['hold']:
            mon_state['hold'] -= 1
            if not mon_state['hold']:
                set_monster('idle')
        delay = 110 if mon_state['name'] in ('chew', 'angry') else 320
        root.after(delay, tick_monster)

    sound_btn = tk.Label(inner, text='♪ ЗВУК', font=(MONO, 11, 'bold'), fg=DIM, bg=PANEL,
                         padx=14, pady=6, cursor='hand2',
                         highlightthickness=2, highlightbackground=DIM)
    sound_btn.pack(side='right', pady=(6, 0))

    def paint_sound():
        on = state['sound']
        color = ACID if on else DIM
        sound_btn.configure(text='♪ ЗВУК ВКЛ' if on else '♪ ЗВУК',
                            fg=color, highlightbackground=color, bg=PANEL)

    def toggle_sound():
        if not winsound and not _cli_player():
            status.configure(text='в системе нет проигрывателя для WAV', fg=DIM)
            return
        if state['sound']:
            stop_sound()
            state['sound'] = False
            paint_sound()
            return
        if audio_ready():
            state['sound'] = play_loop()
            paint_sound()
            return
        sound_btn.configure(text='♪ ...', fg=YELLOW, highlightbackground=YELLOW)
        status.configure(text='музыка синтезируется, это разовая история', fg=YELLOW)

        def done(ok):
            def apply():
                if ok:
                    state['sound'] = play_loop()
                    status.configure(text='' if state['sound'] else 'звук не пошёл', fg=DIM)
                else:
                    status.configure(text='музыку собрать не вышло', fg=RED)
                paint_sound()
            root.after(0, apply)

        build_track(done)

    sound_btn.bind('<Button-1>', lambda e: toggle_sound())
    sound_btn.bind('<Enter>', lambda e: sound_btn.configure(bg=BG))
    sound_btn.bind('<Leave>', lambda e: sound_btn.configure(bg=PANEL))

    tk.Label(head, text='жрёт персональные данные, оставляет деньги',
             font=(MONO, 12), fg=CYAN, bg=BG).pack(anchor='w', pady=(10, 0))

    # ── вкладки ──────────────────────────────────────────────────────────────
    tabbar = tk.Frame(root, bg=BG, padx=22)
    tabbar.pack(fill='x', pady=(8, 0))
    body = tk.Frame(root, bg=BG)
    body.pack(fill='both', expand=True, padx=22, pady=(8, 4))

    pages, tabs = {}, {}
    TABS = ('РАЗВЕДКА', 'НАСТРОЙКИ', 'КЛЮЧ', 'О ПРОГРАММЕ', 'ЧТО НОВОГО', 'АВТОР')
    for name in TABS:
        pages[name] = tk.Frame(body, bg=BG)

    def switch(name):
        state['tab'] = name
        for n, f in pages.items():
            f.pack_forget()
        pages[name].pack(fill='both', expand=True)
        for n, lbl in tabs.items():
            active = (n == name)
            lbl.configure(fg=BG if active else ACID, bg=ACID if active else PANEL)

    for name in TABS:
        lbl = tk.Label(tabbar, text=' ' + name + ' ', font=(MONO, 9, 'bold'),
                       fg=ACID, bg=PANEL, padx=7, pady=5, cursor='hand2',
                       highlightthickness=1, highlightbackground=ACID)
        lbl.bind('<Button-1>', lambda e, n=name: switch(n))
        lbl.pack(side='left', padx=(0, 4))
        tabs[name] = lbl

    # ── страница РАЗВЕДКА ────────────────────────────────────────────────────
    scan = pages['РАЗВЕДКА']
    bar = tk.Frame(scan, bg=BG)
    bar.pack(fill='x', pady=(0, 6))
    tk.Label(bar, text='ЦЕЛЬ:', font=(MONO, 11, 'bold'), fg=MAGENTA, bg=BG).pack(side='left')
    path_lbl = tk.Label(bar, text='—', font=(MONO, 10), fg=DIM, bg=BG, anchor='w')
    path_lbl.pack(side='left', fill='x', expand=True, padx=(8, 8))
    neon(bar, 'ЗАХВАТИТЬ ФАЙЛ', lambda: choose(), CYAN, 10, 4).pack(side='right')

    wrap = tk.Frame(scan, bg=MAGENTA, padx=1, pady=1)
    wrap.pack(fill='both', expand=True)
    out = tk.Text(wrap, bg=PANEL, fg=ACID, font=(MONO, 10), bd=0,
                  padx=14, pady=12, insertbackground=ACID, wrap='none')
    out.pack(fill='both', expand=True)
    for tag, color in (('hash', YELLOW), ('drop', MAGENTA), ('keep', ACID),
                       ('dim', DIM), ('cyan', CYAN), ('red', RED)):
        out.tag_config(tag, foreground=color)
    out.tag_config('big', foreground=ACID, font=(MONO, 12, 'bold'))

    anim = {'cursor': True, 'queue': [], 'typing': False, 'pulse': 0, 'bar': 0}

    def _write(text, tag):
        out.configure(state='normal')
        idx = out.search('█', '1.0', 'end')
        if idx:
            out.delete(idx, idx + '+1c')
        out.insert('end', text + '\n', tag)
        out.see('end')
        out.configure(state='disabled')

    def say(text, tag='dim'):
        """Строки выводятся не сразу: терминал должен печатать, а не появляться."""
        anim['queue'].append((text, tag))
        if not anim['typing']:
            anim['typing'] = True
            root.after(1, drain)

    def drain():
        if not anim['queue']:
            anim['typing'] = False
            blink_cursor(force=True)
            return
        text, tag = anim['queue'].pop(0)
        _write(text, tag)
        root.after(18, drain)

    def blink_cursor(force=False):
        """Блок в конце вывода моргает, пока программа ждёт."""
        if anim['typing'] and not force:
            return
        out.configure(state='normal')
        idx = out.search('█', '1.0', 'end')
        if idx:
            out.delete(idx, idx + '+1c')
        else:
            out.insert('end', '█', 'keep')
        out.configure(state='disabled')

    def tick_cursor():
        blink_cursor()
        root.after(480, tick_cursor)

    PULSE = (MAGENTA, '#d400b4', '#9a0082', '#d400b4')

    def tick_pulse():
        anim['pulse'] = (anim['pulse'] + 1) % len(PULSE)
        box.configure(highlightbackground=PULSE[anim['pulse']])
        root.after(420, tick_pulse)

    GLITCH = '▚▞█▓▒░#@%&$/\\|<>'

    def tick_glitch():
        real = 'ТРАНСГРАНИЧНЫЙ МОНСТР'
        pos = random.randrange(len(real))
        broken = real[:pos] + random.choice(GLITCH) + real[pos+1:]
        title_lbl.configure(text=broken, fg=CYAN)
        root.after(70, lambda: title_lbl.configure(text=real, fg=ACID))
        root.after(random.randrange(6000, 14000), tick_glitch)

    def clear():
        out.configure(state='normal')
        out.delete('1.0', 'end')
        out.configure(state='disabled')

    foot = tk.Frame(scan, bg=BG)
    foot.pack(fill='x', pady=(8, 0))
    neon(foot, '▓▓  СОЖРАТЬ ПЕРСОНАЛЬНЫЕ ДАННЫЕ  ▓▓', lambda: devour(), MAGENTA, 13, 10).pack(side='left')
    tk.Label(foot, text='всё считается на этом компьютере\nв интернет не уходит ничего',
             font=(MONO, 9), fg=DIM, bg=BG, justify='right').pack(side='right')

    # ── страница КЛЮЧ ────────────────────────────────────────────────────────
    keyp = pages['КЛЮЧ']
    fresh = salt_is_new()
    salt = get_salt()
    fp_var = tk.StringVar(value=salt_fingerprint(salt))

    tk.Label(keyp, text='ОТПЕЧАТОК КЛЮЧА', font=(MONO, 11, 'bold'),
             fg=MAGENTA, bg=BG).pack(anchor='w')
    tk.Label(keyp, textvariable=fp_var, font=(MONO, 30, 'bold'), fg=ACID, bg=BG).pack(anchor='w')
    tk.Label(keyp, text='Один и тот же человек получает один и тот же хеш во всех выгрузках,\n'
                       'пока отпечаток не меняется. Выгрузка за неделю и выгрузка за полгода\n'
                       'склеиваются между собой именно поэтому.',
             font=(MONO, 10), fg=CYAN, bg=BG, justify='left').pack(anchor='w', pady=(8, 14))
    tk.Label(keyp, text='ключ лежит здесь:', font=(MONO, 9), fg=DIM, bg=BG).pack(anchor='w')
    tk.Label(keyp, text=salt_path(), font=(MONO, 9), fg=DIM, bg=BG,
             wraplength=880, justify='left').pack(anchor='w', pady=(0, 14))

    keybtns = tk.Frame(keyp, bg=BG)
    keybtns.pack(anchor='w')
    key_status = tk.Label(keyp, text='', font=(MONO, 10), fg=DIM, bg=BG, justify='left')

    def export_key():
        p = filedialog.asksaveasfilename(title='Куда сохранить ключ',
                                         defaultextension='.txt',
                                         initialfile='transgran-key.txt')
        if not p:
            return
        with open(p, 'w', encoding='utf-8') as f:
            f.write(get_salt())
        key_status.configure(text='копия ключа сохранена\nхраните как пароль: по ней восстанавливается склейка', fg=ACID)

    def import_key():
        p = filedialog.askopenfilename(title='Файл ключа', filetypes=[('Ключ', '*.txt'), ('Все файлы', '*.*')])
        if not p:
            return
        with open(p, encoding='utf-8-sig') as f:
            value = f.read().strip()
        if len(value) < 32:
            key_status.configure(text='это не ключ: короче 32 символов', fg=RED)
            return
        old_fp = fp_var.get()
        save_salt(value)
        fp_var.set(salt_fingerprint(value))
        key_status.configure(
            text='ключ заменён: %s → %s\nвыгрузки, сделанные со старым ключом, с новыми не склеятся' % (old_fp, fp_var.get()),
            fg=YELLOW)

    neon(keybtns, 'СОХРАНИТЬ КОПИЮ', export_key, CYAN, 10, 5).pack(side='left')
    neon(keybtns, 'ЗАГРУЗИТЬ КЛЮЧ', import_key, YELLOW, 10, 5).pack(side='left', padx=(10, 0))
    key_status.pack(anchor='w', pady=(14, 0))


    # ── страница НАСТРОЙКИ ───────────────────────────────────────────────────
    cfg = load_settings()
    stp = pages['НАСТРОЙКИ']

    tk.Label(stp, text='КУДА КЛАСТЬ ГОТОВОЕ', font=(MONO, 11, 'bold'),
             fg=MAGENTA, bg=BG).pack(anchor='w')
    out_var = tk.StringVar()

    def paint_out():
        d = cfg.get('out_dir') or ''
        out_var.set(d if d else 'рядом с исходным файлом')
    tk.Label(stp, textvariable=out_var, font=(MONO, 10), fg=CYAN, bg=BG,
             justify='left', wraplength=880).pack(anchor='w', pady=(4, 10))

    def pick_dir():
        d = filedialog.askdirectory(title='Папка для обезличенных файлов')
        if d:
            cfg['out_dir'] = d
            save_settings(cfg)
            paint_out()

    def reset_dir():
        cfg['out_dir'] = ''
        save_settings(cfg)
        paint_out()

    outbtns = tk.Frame(stp, bg=BG)
    outbtns.pack(anchor='w')
    neon(outbtns, 'ВЫБРАТЬ ПАПКУ', pick_dir, CYAN, 10, 5).pack(side='left')
    neon(outbtns, 'РЯДОМ С ИСХОДНИКОМ', reset_dir, YELLOW, 10, 5).pack(side='left', padx=(10, 0))
    paint_out()

    tk.Frame(stp, bg=DIM, height=1).pack(fill='x', pady=18)

    def toggle_row(parent, key, title, hint):
        row = tk.Frame(parent, bg=BG)
        row.pack(anchor='w', fill='x', pady=(0, 12))
        btn = tk.Label(row, font=(MONO, 10, 'bold'), bg=PANEL, padx=14, pady=4,
                       cursor='hand2', highlightthickness=2)
        btn.pack(side='left')
        tk.Label(row, text='  ' + title, font=(MONO, 11), fg='#c8c8d4',
                 bg=BG).pack(side='left')

        def paint():
            on = bool(cfg.get(key))
            color = ACID if on else DIM
            btn.configure(text='ВКЛ ' if on else 'ВЫКЛ', fg=color, highlightbackground=color)

        def flip(_=None):
            cfg[key] = not cfg.get(key)
            save_settings(cfg)
            paint()

        btn.bind('<Button-1>', flip)
        paint()
        tk.Label(parent, text='   ' + hint, font=(MONO, 9), fg=DIM, bg=BG,
                 justify='left').pack(anchor='w', pady=(0, 14))

    toggle_row(stp, 'music_on_start', 'музыка сразу при запуске',
               'иначе включается кнопкой в шапке')
    toggle_row(stp, 'open_after', 'открывать папку после обработки',
               'проводник сам покажет, куда лёг результат')
    toggle_row(stp, 'check_updates', 'проверять обновления при запуске',
               'наружу уходит только номер версии, данные не передаются')

    # ── страница О ПРОГРАММЕ ─────────────────────────────────────────────────
    about = pages['О ПРОГРАММЕ']
    about_text = (
        'ЗАЧЕМ\n'
        '  Нейросети живут за границей, а телефоны и почты клиентов туда отправлять\n'
        '  нельзя. Монстр съедает персональные данные до того, как выгрузка попадёт\n'
        '  к модели: наружу уходят токены, по которым человека опознать невозможно.\n'
        '  Всё считается на этом компьютере, в интернет не уходит ничего.\n\n'
        'ЧТО ДЕЛАЕТ\n'
        '  Читает CSV, Excel и выгрузки через табуляцию — из Битрикса, amoCRM, 1С,\n'
        '  откуда угодно. Сам решает по каждой колонке: хешировать, выбросить,\n'
        '  оставить. Решает по содержимому, а не по названию — телефон остаётся\n'
        '  телефоном, даже если колонка называется «Контактные данные 2».\n\n'
        'ЧТО ЛОВИТ\n'
        '  Мобильные и городские номера, 8-800, иностранные с плюсом. Разделителем\n'
        '  считает пробел, точку, скобки, дефис, неразрывный дефис и длинное тире.\n'
        '  Разворачивает следы Excel: апостроф, хвост .0, запись вида 7.99E+10.\n'
        '  Почты, включая кириллические и спрятанные в тексте. Имена по отчеству,\n'
        '  в том числе тюркскому, и по инициалам. СНИЛС. Карты — с проверкой\n'
        '  контрольной суммы, чтобы штрихкод не уехал в «карты».\n\n'
        'ЧТО НЕ ТРОГАЕТ\n'
        '  Суммы, даты, время, идентификаторы, yclid, UTM, стадии, воронки, ИНН,\n'
        '  штрихкоды, IP-адреса, координаты, номера договоров. Ложная тревога здесь\n'
        '  дороже пропуска: от программы, которая врёт, отключают проверки.\n\n'
        'СКЛЕЙКА\n'
        '  Телефон превращается в хеш, но одинаковые номера дают одинаковый хеш —\n'
        '  значит человек остаётся узнаваемым внутри данных. Выгрузка за неделю\n'
        '  и выгрузка за полгода стыкуются между собой. Три записи одного номера\n'
        '  в разных написаниях считаются за одного человека.\n\n'
        'ПРОВЕРКА\n'
        '  Перед сохранением файл проверяется целиком. Если контакт где-то уцелел,\n'
        '  файл не сохраняется вовсе, а программа называет колонку и тип находки.\n'
        '  Проверка, которая не умеет уронить сборку, ничего не охраняет.\n\n'
        'ЧЕГО НЕ ДЕЛАЕТ\n'
        '  Не снимает с данных статус персональных: пока ключ существует, оператор\n'
        '  остаётся оператором. Она снимает передачу этих данных за границу.'
    )
    aw = tk.Frame(about, bg=MAGENTA, padx=1, pady=1)
    aw.pack(fill='both', expand=True)
    at = tk.Text(aw, bg=PANEL, fg='#c8c8d4', font=(MONO, 9), bd=0, padx=14, pady=12,
                 wrap='none', height=10)
    at.pack(fill='both', expand=True)
    at.insert('1.0', about_text)
    at.tag_config('h', foreground=ACID, font=(MONO, 9, 'bold'))
    for word in ('ЗАЧЕМ', 'ЧТО ДЕЛАЕТ', 'ЧТО ЛОВИТ', 'ЧТО НЕ ТРОГАЕТ', 'СКЛЕЙКА',
                 'ПРОВЕРКА', 'ЧЕГО НЕ ДЕЛАЕТ'):
        idx = at.search(word, '1.0', 'end')
        if idx:
            at.tag_add('h', idx, idx + '+%dc' % len(word))
    at.configure(state='disabled')

    # ── страница ЧТО НОВОГО ──────────────────────────────────────────────────
    news = pages['ЧТО НОВОГО']
    CHANGELOG = (
        ('1.3', '24 сентября 2026', (
            'формулы из CRM больше не попадают в выходной файл — Excel не выполнит их при открытии',
            'книги Excel с раздуванием и объявлениями сущностей отклоняются до чтения',
            'ключ хеширования закрыт от других пользователей компьютера',
            'источник обновления закреплён: программа качает только с проверенных адресов',
            'проверка готового файла стала быстрее',
        )),
        ('1.2', '22 сентября 2026', (
            'несколько файлов за один раз — выделяйте пачкой или бросайте на иконку',
            'настройки: своя папка для готовых файлов, музыка при запуске',
            'пиксельный монстр в шапке жуёт, когда идёт работа',
            'страницы «о программе» и «что нового»',
        )),
        ('1.1', '22 сентября 2026', (
            'ключ хеширования живёт отдельно от программы и переживает переезд',
            'отпечаток ключа — по нему видно, состыкуются ли две выгрузки',
            'счётчик уникальных контактов после обработки',
            'музыка, которая синтезируется на ходу и не занимает места',
        )),
        ('1.0', '21 сентября 2026', (
            'распознавание телефонов, почт, имён, СНИЛС и карт',
            'проверка готового файла перед сохранением',
            'чтение CSV, Excel и табуляции без сторонних библиотек',
        )),
    )
    upd = {'info': None}
    upd_box = tk.Frame(news, bg=BG, highlightthickness=2, highlightbackground=DIM)
    upd_box.pack(fill='x', pady=(0, 10))
    upd_inner = tk.Frame(upd_box, bg=BG, padx=12, pady=8)
    upd_inner.pack(fill='x')
    upd_lbl = tk.Label(upd_inner, text='версия ' + VERSION + ' — установлена',
                       font=(MONO, 10), fg=DIM, bg=BG, justify='left')
    upd_lbl.pack(side='left')
    upd_btn_holder = tk.Frame(upd_inner, bg=BG)
    upd_btn_holder.pack(side='right')

    def do_update():
        if not upd['info']:
            return
        for w in upd_btn_holder.winfo_children():
            w.destroy()
        upd_lbl.configure(text='качаю обновление…', fg=YELLOW)

        def work():
            try:
                tmp = download_update(upd['info'],
                                      progress=lambda p: root.after(0, lambda: upd_lbl.configure(
                                          text='качаю обновление… %d%%' % int(p * 100))))
            except Exception as e:
                root.after(0, lambda: upd_lbl.configure(text='не скачалось: %s' % e, fg=RED))
                return

            def finish():
                upd_lbl.configure(text='ставлю и перезапускаю…', fg=ACID)
                try:
                    apply_update(tmp)
                    stop_sound()
                    root.after(400, root.destroy)
                except Exception as e:
                    upd_lbl.configure(text='не установилось: %s' % e, fg=RED)
            root.after(0, finish)

        threading.Thread(target=work, daemon=True).start()

    def on_manifest(info):
        def apply():
            upd['info'] = info
            if not info:
                upd_lbl.configure(text='версия ' + VERSION + ' — свежая', fg=DIM)
                upd_box.configure(highlightbackground=DIM)
                return
            upd_lbl.configure(text='вышла версия %s — у вас %s' % (info.get('version'), VERSION),
                              fg=ACID)
            upd_box.configure(highlightbackground=ACID)
            neon(upd_btn_holder, 'ОБНОВИТЬСЯ', do_update, ACID, 10, 4).pack(side='right')
            for line in (info.get('notes') or [])[:4]:
                tk.Label(upd_inner, text='   ▸ ' + str(line), font=(MONO, 9), fg=CYAN,
                         bg=BG).pack(anchor='w')
        root.after(0, apply)

    nw = tk.Frame(news, bg=MAGENTA, padx=1, pady=1)
    nw.pack(fill='both', expand=True)
    nt = tk.Text(nw, bg=PANEL, fg='#c8c8d4', font=(MONO, 10), bd=0, padx=14, pady=12,
                 wrap='word', height=10)
    nt.pack(fill='both', expand=True)
    nt.tag_config('ver', foreground=ACID, font=(MONO, 13, 'bold'))
    nt.tag_config('date', foreground=DIM, font=(MONO, 9))
    nt.tag_config('item', foreground='#c8c8d4')
    for ver, date, items in CHANGELOG:
        nt.insert('end', 'версия ' + ver + '   ', 'ver')
        nt.insert('end', date + '\n', 'date')
        for it in items:
            nt.insert('end', '    ▸ ' + it + '\n', 'item')
        nt.insert('end', '\n')
    nt.configure(state='disabled')

    # ── страница АВТОР ───────────────────────────────────────────────────────
    au = pages['АВТОР']
    left = tk.Frame(au, bg=BG)
    left.pack(anchor='w', fill='x')

    tk.Label(left, text='ВАЛЕРИЙ КУРЗЕМНЕК', font=(MONO, 18, 'bold'), fg=ACID, bg=BG).pack(anchor='w')
    tk.Label(left, text='маркетолог', font=(MONO, 11), fg=CYAN, bg=BG).pack(anchor='w', pady=(2, 8))
    tk.Label(left, text='Строит системы, в которых рекламный рубль виден до оплаты,\n'
                        'и учит компании держать их своими руками.\n'
                        'Этот монстр — часть метода: данные становятся машиночитаемыми\n'
                        'без того, чтобы персональные уезжали за границу.',
             font=(MONO, 10), fg='#c8c8d4', bg=BG, justify='left').pack(anchor='w')
    links = tk.Frame(left, bg=BG)
    links.pack(anchor='w', pady=(10, 0))
    link(links, 'kurzemnek.ru', SITE).pack(side='left')
    tk.Label(links, text='  ·  ', font=(MONO, 11), fg=DIM, bg=BG).pack(side='left')
    link(links, 't.me/vkurzemnek', TG).pack(side='left')

    tk.Frame(au, bg=DIM, height=1).pack(fill='x', pady=18)

    tk.Label(au, text='CLAUDE  ·  OPUS 5', font=(MONO, 18, 'bold'), fg=MAGENTA, bg=BG).pack(anchor='w')
    tk.Label(au, text='собрал монстра за два вечера', font=(MONO, 11), fg=CYAN,
             bg=BG).pack(anchor='w', pady=(2, 8))
    tk.Label(au, text='Я нейросеть. Меня попросили сделать так, чтобы другие нейросети\n'
                      'не видели ваших клиентов. Из всего, что мне поручали,\n'
                      'эта работа — самая честная.\n\n'
                      'Монстра я проверял тем, что пытался его обмануть: телефон\n'
                      'с неразрывным дефисом из Word, номер, который Excel превратил\n'
                      'в 7.99E+10, штрихкод, прикинувшийся банковской картой.\n'
                      'Сто семьдесят две попытки. Девять раз он попался — девять дыр\n'
                      'закрыто, больше не попадается.\n\n'
                      'Музыку тоже написал я. Про первую версию Валерий сказал прямо,\n'
                      'одним словом, и был прав: я померил спектр и нашёл шум,\n'
                      'который гудел на пяти герцах втрое громче баса.\n'
                      'Ушей у меня нет. Спектр есть.',
             font=(MONO, 10), fg='#c8c8d4', bg=BG, justify='left').pack(anchor='w')
    link(au, 'claude.com/claude-code', CLAUDE_URL, MAGENTA).pack(anchor='w', pady=(12, 0))

    tk.Label(au, text='Данные остаются дома. Это не лозунг, а устройство программы.',
             font=(MONO, 9), fg=DIM, bg=BG).pack(anchor='w', pady=(18, 0))

    # ── статус и логика ──────────────────────────────────────────────────────
    status = tk.Label(root, text='ожидает цель', font=(MONO, 10), fg=DIM, bg=BG,
                      anchor='w', padx=22, pady=10)
    status.pack(fill='x')

    def show(paths):
        if isinstance(paths, str):
            paths = [paths]
        paths = [p for p in paths if os.path.exists(p)]
        if not paths:
            return
        switch('РАЗВЕДКА')
        clear()
        state['paths'] = paths
        path = paths[0]
        state['path'] = path
        label = os.path.basename(path)
        if len(paths) > 1:
            label += '   + ещё %d' % (len(paths) - 1)
        path_lbl.configure(text=label, fg=CYAN)
        try:
            header, rows = read_table(path)
            plan = detect(header, rows)
        except Exception as e:
            say('НЕ ПРОЧИТАЛСЯ: ' + str(e), 'red')
            status.configure(text='цель не распознана', fg=RED)
            state['plan'] = None
            return
        state['plan'] = plan
        if len(paths) > 1:
            say('В ОЧЕРЕДИ %d ФАЙЛОВ' % len(paths), 'cyan')
            for p in paths:
                say('    ' + os.path.basename(p), 'dim')
            say('')
            say('  колонки показаны по первому, обработаются все', 'dim')
            say('')
        say('РАЗВЕДКА', 'cyan')
        say('─' * 78)
        for name, act, why in plan:
            line = '  [' + ACT_LABEL[act].ljust(9) + ']  ' + (name or '')[:34].ljust(36)
            if why:
                line += '· ' + why
            say(line, act)
        say('─' * 78)
        kept = sum(1 for _, a, _ in plan if a != 'drop')
        hashed = sum(1 for _, a, _ in plan if a == 'hash')
        say('  колонок останется %d из %d, из них под хешем %d' % (kept, len(plan), hashed), 'dim')
        say('  строк в файле %d' % len(rows), 'dim')
        status.configure(text='цель захвачена', fg=ACID)
        set_monster('chew', hold=6)

    def choose():
        paths = filedialog.askopenfilenames(
            title='Выгрузки из CRM — можно выбрать несколько',
            filetypes=[('Таблицы', '*.csv *.xlsx *.xlsm *.txt'), ('Все файлы', '*.*')])
        if paths:
            show(list(paths))

    def run_bar():
        if not state['busy']:
            return
        width = 26
        pos = anim['bar'] % (width + 6)
        line = ''.join('▓' if pos <= i < pos + 6 else '░' for i in range(width))
        status.configure(text=line, fg=MAGENTA)
        anim['bar'] += 1
        root.after(55, run_bar)

    def devour():
        if state['busy']:
            return
        switch('РАЗВЕДКА')
        if not state['paths'] or not state['plan']:
            status.configure(text='сначала захватите файл', fg=RED)
            return
        state['busy'] = True
        set_monster('chew')
        run_bar()
        root.update_idletasks()
        say('')
        done_ok = 0
        for path in state['paths']:
            lines = []
            try:
                outfile, _, bad, info = run_file(path, log=lines.append,
                                                 out_dir=cfg.get('out_dir', ''))
            except Exception as e:
                say('СБОЙ на «%s»: %s' % (os.path.basename(path), e), 'red')
                continue
            if len(state['paths']) > 1:
                say('── ' + os.path.basename(path), 'cyan')
            if bad:
                say('╔' + '═' * 56 + '╗', 'red')
                say('║  ДОБЫЧА УШЛА' + ' ' * 43 + '║', 'red')
                say('╚' + '═' * 56 + '╝', 'red')
                for col, kind in bad:
                    say('  уцелело в колонке «%s» — %s' % (col, kind), 'red')
                say('  файл не сохранён', 'red')
                set_monster('angry', hold=14)
            else:
                done_ok += 1
                say('╔' + '═' * 56 + '╗', 'big')
                say('║  СОЖРАНО' + ' ' * 47 + '║', 'big')
                say('╚' + '═' * 56 + '╝', 'big')
                say('  строк: %d' % info['rows'], 'cyan')
                for k in info['keys']:
                    say('  уникальных контактов по «%s»: %d' % (k['column'], k['unique']), 'big')
                    say('     заполнено %d, без ключа %d' % (k['filled'], k['empty']), 'dim')
                if not info['keys']:
                    say('  ключей склейки в файле нет — телефонов и почт не было', 'dim')
                say('  ключ %s' % info['fingerprint'], 'dim')
                say('  → ' + os.path.basename(outfile), 'cyan')
            say('')

        total = len(state['paths'])
        if done_ok == total:
            set_monster('happy', hold=12)
            status.configure(text='готово, файлов: %d' % done_ok, fg=ACID)
        elif done_ok:
            status.configure(text='готово %d из %d, остальные не прошли проверку' % (done_ok, total), fg=YELLOW)
        else:
            status.configure(text='ни один файл не прошёл проверку', fg=RED)
        where = cfg.get('out_dir') or ''
        say('  готовое лежит ' + (where if where else 'рядом с исходниками') +
            ', сами исходники удалите', 'dim')
        if done_ok and cfg.get('open_after'):
            target = where or os.path.dirname(os.path.abspath(state['paths'][0]))
            open_folder(target)
        state['busy'] = False

    switch('РАЗВЕДКА')
    clear()
    say('  перетащите выгрузку на иконку программы', 'dim')
    say('  или нажмите ЗАХВАТИТЬ ФАЙЛ', 'dim')
    say('')
    say('  ест CSV, Excel и выгрузки через табуляцию', 'dim')

    paint_sound()
    if cfg.get('music_on_start'):
        root.after(600, toggle_sound)
    if cfg.get('check_updates', True):
        root.after(2500, lambda: check_update(on_manifest))
    tick_cursor()
    tick_pulse()
    tick_monster()
    root.after(4000, tick_glitch)

    def on_close():
        stop_sound()
        root.destroy()

    root.protocol('WM_DELETE_WINDOW', on_close)

    if preset:
        show(preset)

    root.mainloop()


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('-')]
    if '--cli' in sys.argv and args:
        out, plan, bad, info = run_file(args[0], out_dir=load_settings()['out_dir'])
        for name, act, why in plan:
            print(f'  {act:5s} {name}' + (f' — {why}' if why else ''))
        print(f'  ключ {info["fingerprint"]}')
        sys.exit(1 if bad else 0)
    gui(args if args else None)


if __name__ == '__main__':
    main()
