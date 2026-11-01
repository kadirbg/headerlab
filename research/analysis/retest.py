"""Test-retest agreement: a re-measured subsample against the main results.

Usage:
    python3 research/analysis/retest.py --first <main-merged.csv> --second <retest main.csv> --out <dir>

For each measure, compares the value of every site reached in both measurements
and reports agreement and Cohen's kappa (binary measures) or agreement only
(CSP class). Every changed site is listed so each change can be explained.
"""

import argparse
import csv
from pathlib import Path

BINARY = [
    'https_erisilir', 'http_https_yonlenir', 'hsts_var', 'hsts_dogru', 'hsts_guclu',
    'clickjacking_korumasi', 'xcto_dogru', 'referrer_dogru', 'permissions_var',
    'csp_var', 'xxss_var', 'hic_baslik_yok_2016',
]
CATEGORICAL = ['csp_sinif']


def kappa(pairs):
    n = len(pairs)
    po = sum(a == b for a, b in pairs) / n
    p1 = sum(a for a, _ in pairs) / n
    p2 = sum(b for _, b in pairs) / n
    pe = p1 * p2 + (1 - p1) * (1 - p2)
    return po, (1.0 if pe == 1 else (po - pe) / (1 - pe))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--first', required=True, type=Path)
    ap.add_argument('--second', required=True, type=Path)
    ap.add_argument('--out', required=True, type=Path)
    a = ap.parse_args()
    read = lambda p: {r['alan_adi']: r for r in csv.DictReader(open(p, encoding='utf-8-sig'))}
    first, second = read(a.first), read(a.second)
    both = sorted(d for d in second if d in first and first[d]['erisim'] == 'ok' and second[d]['erisim'] == 'ok')

    summary, changes = [], []
    for col in BINARY + CATEGORICAL:
        pairs = [(first[d][col], second[d][col]) for d in both]
        for d, (x, y) in zip(both, pairs):
            if x != y:
                changes.append({'olcu': col, 'alan_adi': d, 'ilk': x, 'tekrar': y})
        if col in BINARY:
            po, k = kappa([(x == '1', y == '1') for x, y in pairs])
            summary.append({'olcu': col, 'n': len(pairs), 'degisen': sum(x != y for x, y in pairs), 'uyum': f'{po:.3f}', 'kappa': f'{k:.3f}'})
        else:
            po = sum(x == y for x, y in pairs) / len(pairs)
            summary.append({'olcu': col, 'n': len(pairs), 'degisen': sum(x != y for x, y in pairs), 'uyum': f'{po:.3f}', 'kappa': ''})

    a.out.mkdir(parents=True, exist_ok=True)
    for name, rows in (('tekrar_olcum_ozet.csv', summary), ('tekrar_olcum_degisenler.csv', changes)):
        with open(a.out / name, 'w', newline='', encoding='utf-8-sig') as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ['olcu'])
            w.writeheader()
            w.writerows(rows)
    total = sum(int(s['n']) for s in summary)
    same = total - sum(int(s['degisen']) for s in summary)
    print(f'{len(both)} sites reached in both; overall agreement {same}/{total} = {same / total:.3f}')
    for s in summary:
        print(s)


if __name__ == '__main__':
    main()
