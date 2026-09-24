#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Готовит выпуск: считает контрольную сумму и пишет манифест обновления.

  python release.py --version 1.3 --base https://kurzemnek.ru/monstr \
      --note "несколько файлов за раз" --note "своя папка для результатов"

Кладёт рядом latest.json. Его и файл программы заливаем в одну папку на сайте —
дальше установленные копии увидят новую версию сами.
"""
import argparse
import hashlib
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description='Манифест обновления')
    ap.add_argument('--version', required=True)
    ap.add_argument('--base', default='https://github.com/kurzemnek/transgran-monstr/releases/latest/download',
                    help='папка на сайте, куда заливаются файлы')
    ap.add_argument('--exe', default=os.path.join(HERE, 'TRANSGRAN-MONSTR.exe'))
    ap.add_argument('--mac', default=os.path.join(HERE, 'TRANSGRAN-MONSTR-mac.zip'))
    ap.add_argument('--note', action='append', default=[])
    ap.add_argument('--out', default=os.path.join(HERE, 'latest.json'))
    a = ap.parse_args()

    if not os.path.exists(a.exe):
        raise SystemExit('нет файла ' + a.exe)
    data = {
        'version': a.version,
        'url': a.base.rstrip('/') + '/' + os.path.basename(a.exe),
        'sha256': sha256(a.exe),
        'size': os.path.getsize(a.exe),
        'notes': a.note,
    }
    if os.path.exists(a.mac):
        data['mac'] = {
            'url': a.base.rstrip('/') + '/' + os.path.basename(a.mac),
            'sha256': sha256(a.mac),
            'size': os.path.getsize(a.mac),
        }
    with open(a.out, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(a.out)
    print(json.dumps(data, ensure_ascii=False, indent=2))
    print('\nЗалить в одну папку на сайте: %s и %s' %
          (os.path.basename(a.exe), os.path.basename(a.out)))


if __name__ == '__main__':
    main()
