#!/usr/bin/env python3
"""Compare PE struct and constant definitions between winnt.h and src/pe.rs."""

import re
import sys
from pathlib import Path


def normalize(name):
    s = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', '_', name)
    s = re.sub(r'(?<=[A-Z])(?=[A-Z][a-z])', '_', s)
    return s.upper()


def print_norm(orig, norm):
    if orig == norm:
        print(f"  {orig}")
    else:
        print(f"  {orig} -> {norm}")


def ordered_norm(items):
    items.sort(key=lambda x: x[0])
    return {norm: (name, norm) for _, name, norm in items}


def extract_image_format(text):
    start = re.search(r'^// Image Format\s*$', text, re.MULTILINE)
    end = re.search(r'^// End Image Format\s*$', text, re.MULTILINE)
    if start and end:
        return text[start.start():end.end()]
    return text


def parse_winnt_h(path):
    text = extract_image_format(path.read_text())
    items = []

    # struct _NAME { or union _NAME {
    for m in re.finditer(
        r'(?:struct|union)\s+(?:\w+\s+)?_?(\w+)\s*\{',
        text
    ):
        name = m.group(1).lstrip('_')
        items.append((m.start(), name, normalize(name)))

    # #define NAME value
    for m in re.finditer(r'^#\s*define\s+([A-Z]\w+)\s', text, re.MULTILINE):
        name = m.group(1)
        items.append((m.start(), name, name.upper()))

    # NAME = value,
    for m in re.finditer(r'^\s+(\w+)\s*=\s*\w+', text, re.MULTILINE):
        name = m.group(1)
        items.append((m.start(), name, name.upper()))

    return ordered_norm(items)


def parse_pe_rs(path):
    text = path.read_text()
    items = []

    # pub struct Name
    for m in re.finditer(r'^pub struct (\w+)', text, re.MULTILINE):
        name = m.group(1)
        items.append((m.start(), name, normalize(name)))

    # pub const NAME:
    for m in re.finditer(r'^pub const (\w+)\s*:', text, re.MULTILINE):
        name = m.group(1)
        items.append((m.start(), name, name.upper()))

    # NAME = value,
    for m in re.finditer(r'^\s+(\w+)\s*=\s*-?[\w.]+\s*[,=]', text, re.MULTILINE):
        name = m.group(1)
        items.append((m.start(), name, name.upper()))

    return ordered_norm(items)


def main():
    winnt_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('.') / 'winnt.h'
    winnt = parse_winnt_h(winnt_path)
    pe = parse_pe_rs(Path('.') / 'src' / 'pe.rs')

    only_winnt = [k for k in winnt if k not in pe]
    only_pe = [k for k in pe if k not in winnt]

    print("=== in winnt.h but not in pe.rs ===")
    for k in only_winnt:
        print_norm(*winnt[k])

    print("\n=== in pe.rs but not in winnt.h ===")
    for k in only_pe:
        print_norm(*pe[k])


if __name__ == '__main__':
    main()
