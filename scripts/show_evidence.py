#!/usr/bin/env python3
"""Print a saved, redacted demonstration report; never connect to a server."""
import argparse
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('view', choices=('before', 'after'))
args = parser.parse_args()
report = Path(__file__).resolve().parent.parent / 'assets' / (args.view + '.txt')
print(report.read_text(encoding='utf-8'), end='')
