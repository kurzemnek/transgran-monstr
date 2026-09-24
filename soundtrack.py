#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Процедурный lo-fi саундтрек монстра. Оригинальная музыка, синтезируется кодом.

Ничего не скачивается и не сэмплируется: волны считаются здесь, поэтому трек
можно раздавать вместе с программой без чужих прав.

Звучание — 16-битная эра: квадратные и пилообразные волны, квантование до
десяти бит, частота 16 кГц, длинная задержка. Лад фригийский доминантный от ре,
темп медленный — тот самый пустынный минор.

  python soundtrack.py                  — луп 150 секунд рядом со скриптом
  python soundtrack.py --minutes 10     — десятиминутная версия
  python soundtrack.py --out путь.wav
"""

import argparse
import array
import math
import os
import random
import struct
import wave

SR = 22050          # ниже брать нельзя: квадратные волны начинают зеркалить
BITS = 14           # до скольки бит прижимаем перед выдачей в 16
BPM = 68
BEAT = 60.0 / BPM
BAR = BEAT * 4

# Фригийский доминантный от ре: D Eb F# G A Bb C
SCALE = (0, 1, 4, 5, 7, 8, 10)
ROOT = 146.83       # ре малой октавы

# Гармония: по такту на аккорд, восемь тактов круг.
# Ступени лада, снизу вверх.
CHORDS = (
    (0, 3, 7),      # ре минор
    (0, 3, 7),
    (-4, 0, 3),     # си-бемоль
    (-4, 0, 3),
    (-7, -4, 0),    # соль минор
    (-7, -4, 0),
    (-5, -1, 2),    # ля с пониженной второй
    (-5, -1, 2),
)


# Рисунки арпеджио по частям. None — пауза, число — ступень аккорда
# (ступени выше третьей берутся октавой выше).
ARP_PATTERNS = (
    (0, None, 2, None, 1, None, 2, None),
    (0, 2, 1, 3, 0, 2, 1, 4),
    (0, 2, 4, 2, 1, 3, 5, 3),
    (0, None, 1, 2, None, 2, 1, None),
)

# Мелодические фразы ступенями лада. Меняются каждые два такта.
MELODY = (
    (0, 2, 4, 2),
    (4, 3, 2, 0),
    (2, 4, 5, 4),
    (0, 4, 3, 1),
    (5, 4, 2, 4),
    (1, 2, 4, 6),
)


def voice(freq, lo=168.0, hi=760.0):
    """Держит голос в своём регистре.

    Аккорды ходят по ладу вниз, и на соль-миноре подушка падала к 116 Гц —
    ровно туда, где уже сидит бас. Вдвоём они и давали гудение. Октавный
    перенос оставляет гармонию прежней, но разводит голоса по этажам.
    """
    while freq < lo:
        freq *= 2.0
    while freq > hi:
        freq /= 2.0
    return freq


def note(semitone, octave=0):
    return ROOT * (2 ** ((semitone + 12 * octave) / 12.0))


def table_saw(size=1024):
    return [2.0 * i / size - 1.0 for i in range(size)]


def table_square(size=1024, harmonics=9):
    """Квадрат, собранный из нечётных гармоник.

    Идеальная ступенька читается фазовым аккумулятором с шагом в десятки
    отсчётов — сглаживать её в таблице бесполезно, всё равно попадаем на обрыв.
    Сумма ограниченного числа гармоник даёт тот же тембр без вертикалей
    и без зеркальных частот.
    """
    out = []
    for i in range(size):
        v = 0.0
        k = 1
        while k <= harmonics:
            v += math.sin(2 * math.pi * k * i / size) / k
            k += 2
        out.append(v * 4.0 / math.pi / 1.18)
    return out


def table_sine(size=1024):
    return [math.sin(2 * math.pi * i / size) for i in range(size)]


def table_tri(size=1024):
    half = size // 2
    return [(4.0 * i / size - 1.0) if i < half else (3.0 - 4.0 * i / size)
            for i in range(size)]


def soften(table, passes=3):
    """Заваливает вертикальные фронты скользящим средним.

    Идеальный квадрат обрывается дважды за период. На низкой частоте
    дискретизации это и зеркалит, и стучит; пара проходов сглаживания
    оставляет характер, но убирает вертикали.
    """
    t = list(table)
    size = len(t)
    for _ in range(passes):
        t = [(t[i - 1] + 2 * t[i] + t[(i + 1) % size]) / 4.0 for i in range(size)]
    return t


def centered(table):
    """Снимает постоянную составляющую.

    У квадрата со скважностью 0.25 среднее равно -0.5: каждая нота арпеджио
    толкает мембрану в одну сторону, и на огибающей это слышно как низкочастотный
    хрип поверх музыки. Ноль по среднему — обязательное условие, а не тонкость.
    """
    dc = sum(table) / len(table)
    return [v - dc for v in table]


SAW = centered(soften(table_saw(), 3))
SQR = centered(table_square())
TRI = centered(table_tri())
SIN = centered(table_sine())


ATTACK = int(0.008 * SR)      # восемь миллисекунд подъёма


def osc(buf, table, freq, start, length, amp, env=None, vibrato=0.0):
    """Кладёт в буфер одну ноту. Фазовый аккумулятор по таблице — дёшево.

    Нота обязана начинаться с нуля и по фазе, и по громкости. Мгновенный старт
    на полной амплитуде — это щелчок; восемь нот арпеджио в такт превращают
    его в непрерывный треск поверх музыки.
    """
    size = len(table)
    phase = 0.0
    for i in range(length):
        n = start + i
        if n >= len(buf):
            break
        f = freq
        if vibrato:
            f *= 1.0 + vibrato * math.sin(2 * math.pi * 5.2 * n / SR)
        phase += size * f / SR
        if phase >= size:
            phase -= size * int(phase / size)
        a = amp * (env(i / length) if env else 1.0)
        if i < ATTACK:
            a *= i / ATTACK
        tail = length - i
        if tail < ATTACK:
            a *= tail / ATTACK
        buf[n] += table[int(phase)] * a


def env_pluck(t):
    return math.exp(-4.5 * t)


def env_pad(t):
    if t < 0.25:
        return t / 0.25
    if t > 0.75:
        return (1.0 - t) / 0.25
    return 1.0


def env_hit(t):
    return math.exp(-22.0 * t)


# Громкость по настроениям: первая восьмёрка — почти пустая, третья — полная,
# четвёртая уводит обратно в песок. Без этого трек звучит одной плоской стеной.
SECTION_GAIN = (0.68, 0.88, 1.0, 0.74)
WIND_GAIN = (1.0, 0.7, 0.5, 0.85)
# Шумовой слой выключен: на любом уровне широкополосный шум остаётся шипением,
# а атмосферу здесь держат дрон и задержка. Включать только осознанно.
WIND = False


def section_of(sample_index):
    return int(sample_index / SR / BAR / 8) % 4


def wind(buf, seed=7):
    """Песок, а не рокот.

    Первая версия фильтровала шум на 12 Гц и выводила его в полтора раза громче
    баса: слышно это было как непрерывный низкочастотный хрип, потому что
    динамик отрабатывал такие колебания ходом мембраны, а не звуком. Ветру
    нужна середина и верх — полоса примерно от трёхсот герц до четырёх килогерц.
    """
    if not WIND:
        return
    rnd = random.Random(seed)
    lo = hi = 0.0
    a_lo = 1.0 - math.exp(-2 * math.pi * 2400.0 / SR)      # потолок шипения
    a_hi = 1.0 - math.exp(-2 * math.pi * 260.0 / SR)       # пол шипения
    for n in range(len(buf)):
        white = rnd.uniform(-1, 1)
        lo += a_lo * (white - lo)
        hi += a_hi * (lo - hi)
        band = lo - hi                                      # полосовой шум
        breath = 0.55 + 0.45 * math.sin(2 * math.pi * n / (SR * 17.0))
        gust = 0.75 + 0.25 * math.sin(2 * math.pi * n / (SR * 4.3))
        buf[n] += band * 0.07 * breath * gust * WIND_GAIN[section_of(n)]


def build(seconds, seed=20260921):
    rnd = random.Random(seed)
    total = int(seconds * SR)
    buf = [0.0] * total
    wind(buf, seed)

    bars = int(seconds / BAR) + 1
    for bar in range(bars):
        t0 = bar * BAR
        start = int(t0 * SR)
        if start >= total:
            break
        chord = CHORDS[bar % len(CHORDS)]
        section = (bar // 8) % 4
        g = SECTION_GAIN[section]
        inner = bar % 8            # место внутри восьмёрки

        # Бас держит корень, но сидит тихо: вдвоём с подушкой они забивали
        # полосу 60-160 Гц на три четверти, и это читалось как гудение.
        osc(buf, SIN, voice(note(chord[0], -1), 62.0, 120.0), start, int(BAR * SR), 0.13 * g,
            env_pad, vibrato=0.004)

        # Подушка ушла на октаву вверх — в середину, где было пусто.
        for st in chord[1:]:
            osc(buf, TRI, voice(note(st, 0)), start, int(BAR * SR), 0.11 * g, env_pad)

        # Арпеджио: у каждой части свой рисунок, иначе круг слышен насквозь.
        pattern = ARP_PATTERNS[section]
        step = BEAT / 2
        for k, deg in enumerate(pattern):
            if deg is None:
                continue
            s0 = start + int(k * step * SR)
            st_ = chord[deg % len(chord)] + 12 * (deg // len(chord))
            osc(buf, SQR, voice(note(st_, 0), 220.0, 640.0), s0, int(step * SR * 0.95),
                0.13 * g, env_pluck)

        # Мелодия идёт всюду, меняя плотность: это и есть «живее».
        phrase = MELODY[(bar // 2) % len(MELODY)]
        beats = ((0,), (0, 2), (0, 1.5, 2.5), (0, 1, 2, 3))[section]
        if True:
            for j, bt in enumerate(beats):
                deg = phrase[j % len(phrase)]
                s0 = start + int(bt * BEAT * SR)
                octv = 1 if (inner % 4 != 3) else 2
                osc(buf, TRI, voice(note(SCALE[deg % len(SCALE)], octv), 330.0, 1050.0), s0,
                    int(BEAT * SR * 1.3), 0.13 * g, env_pluck)

        # Контрлиния — редкая, снизу, чтобы было за что зацепиться уху.
        if section in (2, 3) and inner % 2 == 1:
            osc(buf, TRI, voice(note(chord[1], 0), 200.0, 560.0), start + int(2.5 * BEAT * SR),
                int(BEAT * SR * 1.2), 0.08 * g, env_pluck)

        # Удар на первую и третью
        if section != 0:
            for k in (0, 2):
                s0 = start + int(k * BEAT * SR)
                osc(buf, SIN, voice(note(chord[0], -1), 62.0, 120.0), s0, int(0.14 * SR), 0.12 * g, env_hit)

    delay(buf, int(BEAT * 0.75 * SR), 0.22)
    highpass(buf)
    lowpass(buf)
    return buf


def highpass(buf, cutoff=70.0, stages=3):
    """Срезает всё, что колонка отдаёт хлопками вместо тона.

    Одного звена мало: на тридцати герцах оно оставляет почти сорок процентов
    амплитуды. Три звена подряд дают достаточную крутизну.
    """
    k = math.exp(-2 * math.pi * cutoff / SR)
    for _ in range(stages):
        prev_in = prev_out = 0.0
        for n in range(len(buf)):
            x = buf[n]
            prev_out = k * (prev_out + x - prev_in)
            prev_in = x
            buf[n] = prev_out


def lowpass(buf, cutoff=5200.0):
    """Снимает песок от квадратных волн на низкой частоте дискретизации."""
    a = 1.0 - math.exp(-2 * math.pi * cutoff / SR)
    y = 0.0
    for n in range(len(buf)):
        y += a * (buf[n] - y)
        buf[n] = y


def delay(buf, samples, feedback):
    """Лента: эхо в три четверти доли, как положено жанру."""
    for n in range(samples, len(buf)):
        buf[n] += buf[n - samples] * feedback


def crush(x, bits=BITS):
    levels = (1 << bits) - 1
    return round(x * levels) / levels


def seamless(buf, tail_seconds=4.0):
    """Кроссфейд хвоста с началом, чтобы петля не щёлкала на стыке."""
    tail = int(tail_seconds * SR)
    if tail * 2 >= len(buf):
        return buf
    out = buf[:-tail]
    for i in range(tail):
        k = i / tail
        out[i] = out[i] * k + buf[len(buf) - tail + i] * (1.0 - k)
    return out


def render_bytes(seconds=110.0, seed=20260921, loop=True):
    """Тот же трек, но готовым WAV в памяти.

    Программе не нужен файл на диске: winsound умеет играть из байтов,
    поэтому музыка живёт внутри процесса и наружу ничего не кладётся.
    """
    import io as _io
    buf = _build_samples(seconds, seed, loop)
    bio = _io.BytesIO()
    with wave.open(bio, 'wb') as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(SR)
        w.writeframes(buf.tobytes())
    return bio.getvalue()


def _build_samples(seconds, seed, loop):
    buf = build(seconds + (4.0 if loop else 0.0), seed)
    if loop:
        buf = seamless(buf)
    peak = max(abs(v) for v in buf) or 1.0
    gain = 0.78 / peak
    data = array.array('h')
    for v in buf:
        s = max(-1.0, min(1.0, v * gain))
        data.append(int(crush(s) * 32000))
    return data


def render(seconds=150.0, path=None, seed=20260921, loop=True):
    data = _build_samples(seconds, seed, loop)
    path = path or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dune_lofi.wav')
    with wave.open(path, 'wb') as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(SR)
        w.writeframes(data.tobytes())
    return path, len(data) / float(SR)


def main():
    ap = argparse.ArgumentParser(description='Процедурный lo-fi трек')
    ap.add_argument('--minutes', type=float, default=2.5)
    ap.add_argument('--out', default=None)
    ap.add_argument('--seed', type=int, default=20260921)
    ap.add_argument('--no-loop', action='store_true')
    a = ap.parse_args()
    path, dur = render(a.minutes * 60.0, a.out, a.seed, not a.no_loop)
    size = os.path.getsize(path) / 1048576.0
    print('%s\n%.1f сек, %.1f МБ, %d Гц, 16 бит моно' % (path, dur, size, SR))


if __name__ == '__main__':
    main()
