#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Synthetic regression cases for sparse CRM/1C exports (standard library only).

Run: python test_regressions.py
No customer fixtures, real settings, persistent keys, or network are used.
"""
import csv
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from xml.sax.saxutils import escape
import zipfile

import anonymizer as A


class SparseExportRegressions(unittest.TestCase):
    SALT = 'synthetic-regression-key-not-a-user-key'
    PII = {
        'телефон': 'контакт для доставки: +7 999 123-45-67, звонить по заявке',
        'почта': 'контакт для доставки: synthetic@example.org, писать по заявке',
        'имя': 'получатель по заявке: Иванов И.И., доставка по согласованию',
        'карта': 'реквизит по заявке: 4111111111111111, согласовать оплату',
        'СНИЛС': 'реквизит по заявке: 123-456-789 01, проверить документ',
    }

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='monster-regressions-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.salt_patch = patch.object(A, 'get_salt', return_value=self.SALT)
        self.salt_patch.start()
        self.addCleanup(self.salt_patch.stop)

    def write_csv(self, name, header, rows):
        path = self.root / name
        with path.open('w', encoding='utf-8-sig', newline='') as stream:
            writer = csv.writer(stream, delimiter=';')
            writer.writerow(header)
            writer.writerows(rows)
        return path

    def assert_drop_and_clean_output(self, rows):
        header = ['Номер', 'Основание', 'Сумма']
        plan = A.detect(header, rows)
        self.assertEqual(plan[1][1], 'drop')
        out_header, out_rows = A.process(header, rows, plan, self.SALT)
        self.assertEqual(out_header, ['Номер', 'Сумма'])
        self.assertEqual(out_rows, [[row[0], row[2]] for row in rows])
        self.assertEqual(A.gate(out_header, out_rows), [])

    def test_late_pii_after_empty_prefix_is_removed_before_gate(self):
        for kind, text in self.PII.items():
            with self.subTest(kind=kind):
                rows = [[str(i), '', '1200.50'] for i in range(620)]
                rows.append(['620', text, '2400.75'])
                self.assert_drop_and_clean_output(rows)

    def test_rare_pii_after_nonempty_prefix_is_removed_before_gate(self):
        for kind, text in self.PII.items():
            with self.subTest(kind=kind):
                rows = [[str(i), 'обычная поставка', '1200.50'] for i in range(620)]
                rows.append(['620', text, '2400.75'])
                self.assert_drop_and_clean_output(rows)

    def test_run_file_saves_late_pii_exports(self):
        for kind, text in self.PII.items():
            with self.subTest(kind=kind):
                rows = [[str(i), '', '1200.50'] for i in range(620)]
                rows.append(['620', text, '2400.75'])
                path = self.write_csv(kind + '.csv', ['Номер', 'Основание', 'Сумма'], rows)
                output, plan, bad, info = A.run_file(str(path), log=lambda *_: None)
                self.assertEqual(plan[1][1], 'drop')
                self.assertEqual(bad, [])
                self.assertIsNotNone(output)
                self.assertEqual(info['rows'], len(rows))
                out_header, out_rows = A.read_table(output)
                self.assertEqual(A.gate(out_header, out_rows), [])
                self.assertEqual(out_rows, [[row[0], row[2]] for row in rows])

    def test_late_real_phone_column_is_hashed(self):
        rows = [[''] for _ in range(620)] + [
            ['+7 999 123-45-67'], ['8 (999) 123-45-67'], ['79991234567'],
        ]
        plan = A.detect(['Поле 2'], rows)
        self.assertEqual(plan[0][1], 'hash')
        header, output = A.process(['Поле 2'], rows, plan, self.SALT)
        self.assertEqual(output[:620], [[''] for _ in range(620)])
        self.assertEqual(len(set(row[0] for row in output[620:])), 1)
        self.assertTrue(output[-1][0])
        self.assertEqual(A.gate(header, output), [])

    def test_late_real_email_column_is_hashed(self):
        rows = [[''] for _ in range(620)] + [
            ['synthetic@example.org'], ['SYNTHETIC@EXAMPLE.ORG'],
        ]
        plan = A.detect(['Поле 2'], rows)
        self.assertEqual(plan[0][1], 'hash')
        header, output = A.process(['Поле 2'], rows, plan, self.SALT)
        self.assertEqual(output[-1], output[-2])
        self.assertTrue(output[-1][0])
        self.assertEqual(A.gate(header, output), [])

    def test_smaller_sample_cannot_bypass_full_column_check(self):
        for kind, text in self.PII.items():
            with self.subTest(kind=kind):
                rows = [['обычная поставка'] for _ in range(5)] + [[text]]
                plan = A.detect(['Основание'], rows, sample=1)
                self.assertEqual(plan[0][1], 'drop')
                header, output = A.process(['Основание'], rows, plan, self.SALT)
                self.assertEqual(A.gate(header, output), [])

    def test_none_sample_scans_late_contacts_and_rare_pii(self):
        header = ['Поле 1', 'Поле 2', 'Основание']
        rows = [['', '', 'обычная поставка'] for _ in range(620)]
        rows += [['+7 999 123-45-67', 'synthetic@example.org', 'обычная поставка'],
                 ['8 (999) 123-45-67', 'SYNTHETIC@EXAMPLE.ORG', self.PII['имя']]]
        plan = A.detect(header, rows, sample=None)
        self.assertEqual([action for _, action, _ in plan], ['hash', 'hash', 'drop'])
        out_header, out_rows = A.process(header, rows, plan, self.SALT)
        self.assertEqual(out_rows[-1], out_rows[-2])
        self.assertTrue(all(out_rows[-1]))
        self.assertEqual(A.gate(out_header, out_rows), [])

    def test_product_descriptions_are_not_initials(self):
        for text in (
            'РЕЗИНА. Сотовая структура',
            'МЕТАЛЛ. Размер 2500 х 950 мм',
            'ПЛАСТИК. Размер 1000 мм',
            'ЗАО РЕСУРС. Знаки',
            'ДОРОЖНИК НА ЯМАЛЕ. Берут периодически',
        ):
            with self.subTest(text=text):
                self.assertFalse(A.looks_like_name(text, weak=False))
                self.assertIsNone(A.has_pii(text))
                plan = A.detect(['Основание'], [[text]])
                self.assertEqual(plan[0][1], 'keep')
                self.assertEqual(A.gate(['Основание'], [[text]]), [])

    def test_actual_initials_still_detected_in_both_orders(self):
        for text in (
            'Иванов И.И.', 'И. И. Иванов', 'И.И.Иванов', 'Иванов И.',
            'И. Иванов', 'ИП Иванов И.И.', 'директор Петрова М.С.',
            '(Петрова А.А.)', 'получатель: А.А. Петрова',
            'Иванов-Петров И.И.', 'А.А. Иванова-Петрова',
        ):
            with self.subTest(text=text):
                self.assertTrue(A.looks_like_name(text, weak=False))
                self.assertEqual(A.has_pii(text), 'имя')

    def test_safe_business_fields_and_duplicate_headers_are_preserved(self):
        header = ['Номер', 'Дата', 'Сумма', 'Состояние', 'Номер']
        rows = [['0000-000001', '16.11.2026', '129000.50', 'Оплачено', '0000-000002'],
                ['0000-000003', '2026-11-16', '49000', 'В работе', '0000-000004']]
        plan = A.detect(header, rows)
        self.assertEqual([action for _, action, _ in plan], ['keep'] * len(header))
        out_header, out_rows = A.process(header, rows, plan, self.SALT)
        self.assertEqual((out_header, out_rows), (header, rows))
        self.assertEqual(A.gate(out_header, out_rows), [])

    def test_duplicate_headers_do_not_hide_late_contact_column(self):
        rows = [['0000-000001', 'обычная поставка'] for _ in range(620)]
        rows.append(['0000-000002', self.PII['телефон']])
        plan = A.detect(['Основание', 'Основание'], rows)
        self.assertEqual([action for _, action, _ in plan], ['keep', 'drop'])
        header, output = A.process(['Основание', 'Основание'], rows, plan, self.SALT)
        self.assertEqual(header, ['Основание'])
        self.assertEqual(output, [[row[0]] for row in rows])
        self.assertEqual(A.gate(header, output), [])

    def test_gate_still_blocks_deliberately_kept_late_contact(self):
        for kind, text in self.PII.items():
            with self.subTest(kind=kind):
                header = ['Основание']
                rows = [['обычная поставка'] for _ in range(620)] + [[text]]
                output_header, output_rows = A.process(
                    header, rows, [('Основание', 'keep', '')], self.SALT)
                bad = A.gate(output_header, output_rows)
                self.assertEqual(bad, [('Основание', kind)])
                self.assertNotIn(text, repr(bad))

    def test_run_file_gate_failure_still_prevents_output(self):
        text = self.PII['телефон']
        path = self.write_csv('manual-keep.csv', ['Основание'], [[text]])
        with patch.object(A, 'detect', return_value=[('Основание', 'keep', '')]):
            output, _, bad, _ = A.run_file(str(path), log=lambda *_: None)
        self.assertIsNone(output)
        self.assertEqual(bad, [('Основание', 'телефон')])
        self.assertFalse((self.root / 'manual-keep_обезличено.csv').exists())

    def test_sparse_xlsx_end_to_end(self):
        header = ['Номер', 'Дата', 'Сумма', 'Менеджер', 'Документ-основание', 'Номер']
        rows = [['0000-%06d' % i, '16.11.2026', '1200.50', 'Иванов И.И.', '',
                 '0001-%06d' % i] for i in range(620)]
        rows.append(['0000-000620', '16.11.2026', '2400.75', 'Иванов И.И.',
                     self.PII['телефон'], '0001-000620'])
        ns = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'
        xml_rows = []
        for row_index, values in enumerate([header] + rows, 1):
            cells = ''.join('<c r="%s%d" t="inlineStr"><is><t>%s</t></is></c>'
                            % (A.index_col(column), row_index, escape(value))
                            for column, value in enumerate(values))
            xml_rows.append('<row r="%d">%s</row>' % (row_index, cells))
        path = self.root / 'synthetic-sparse.xlsx'
        with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as book:
            book.writestr('xl/worksheets/sheet1.xml',
                          '<worksheet xmlns="%s"><sheetData>%s</sheetData></worksheet>'
                          % (ns, ''.join(xml_rows)))
        output, plan, bad, info = A.run_file(str(path), log=lambda *_: None)
        self.assertIsNotNone(output)
        self.assertEqual([action for _, action, _ in plan],
                         ['keep', 'keep', 'keep', 'drop', 'drop', 'keep'])
        self.assertEqual(bad, [])
        out_header, out_rows = A.read_table(output)
        self.assertEqual(out_header, [header[i] for i in (0, 1, 2, 5)])
        self.assertEqual(out_rows, [[row[i] for i in (0, 1, 2, 5)] for row in rows])
        self.assertEqual(info['rows'], len(rows))
        self.assertEqual(A.gate(out_header, out_rows), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
