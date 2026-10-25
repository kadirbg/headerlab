"""Agreement between the research classification and MDN HTTP Observatory.

Usage:
    python3 research/validation/compare_observatory.py --run-dir <output/dogrulama-1> --dest <dir>

Reads <run-dir>/main.csv (classify.ts on the validation scan) and
<run-dir>/observatory.jsonl (observatory.ts), both measured at the same time
from the same connection. For each comparable check it reports both-positive,
only-v1, only-Observatory, both-negative, percent agreement and Cohen's kappa,
and lists every disagreeing site so each can be explained.

Mapping (Observatory test result values counted as positive):
    hsts_dogru            strict-transport-security: hsts-implemented-max-age-at-least-six-months, hsts-preloaded
    http_https_yonlenir   redirection: redirection-to-https, redirection-all-redirects-preloaded
    clickjacking_korumasi x-frame-options: x-frame-options-sameorigin-or-deny, x-frame-options-implemented-via-csp
    xcto_dogru            x-content-type-options: x-content-type-options-nosniff
    referrer_dogru        referrer-policy: referrer-policy-private
    csp_var               content-security-policy: anything but csp-not-implemented*
    csp_koruyucu          content-security-policy: csp-implemented-with-no-unsafe*
    coop_var              cross-origin-opener-policy: anything but coop-not-implemented
    cerez_tum_secure      cookies (sites that set cookies): no *without-secure-flag* result
"""

import argparse
import csv
import json
from pathlib import Path

CHECKS = {
    'hsts_dogru': ('strict-transport-security', lambda r: r in ('hsts-implemented-max-age-at-least-six-months', 'hsts-preloaded')),
    'http_https_yonlenir': ('redirection', lambda r: r in ('redirection-to-https', 'redirection-all-redirects-preloaded')),
    'clickjacking_korumasi': ('x-frame-options', lambda r: r in ('x-frame-options-sameorigin-or-deny', 'x-frame-options-implemented-via-csp')),
    'xcto_dogru': ('x-content-type-options', lambda r: r == 'x-content-type-options-nosniff'),
    'referrer_dogru': ('referrer-policy', lambda r: r == 'referrer-policy-private'),
    'csp_var': ('content-security-policy', lambda r: not r.startswith('csp-not-implemented')),
    'csp_koruyucu': ('content-security-policy', lambda r: r.startswith('csp-implemented-with-no-unsafe')),
    'coop_var': ('cross-origin-opener-policy', lambda r: r != 'coop-not-implemented'),
    'cerez_tum_secure': ('cookies', lambda r: 'without-secure-flag' not in r),
}


def v1_value(row: dict, col: str):
    if col == 'csp_koruyucu':
        return row['csp_sinif'] in ('kismen_etkili', 'etkili')
    if col == 'cerez_tum_secure' and row['cerez_tum_secure'] == '':
        return None  # no cookies: not comparable
    return row[col] == '1'


def kappa(pairs):
    n = len(pairs)
    a = sum(1 for x, y in pairs if x and y)
    d = sum(1 for x, y in pairs if not x and not y)
    po = (a + d) / n
    p1 = sum(1 for x, _ in pairs if x) / n
    p2 = sum(1 for _, y in pairs if y) / n
    pe = p1 * p2 + (1 - p1) * (1 - p2)
    return po, (1.0 if pe == 1 else (po - pe) / (1 - pe))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--run-dir', required=True, type=Path)
    ap.add_argument('--dest', required=True, type=Path)
    a = ap.parse_args()

    rows = {r['alan_adi']: r for r in csv.DictReader(open(a.run_dir / 'main.csv', encoding='utf-8-sig')) if r['erisim'] == 'ok'}
    obs = {}
    for line in open(a.run_dir / 'observatory.jsonl', encoding='utf-8'):
        o = json.loads(line)
        if 'tests' in o['result']:
            obs[o['host']] = o['result']['tests']
    hosts = sorted(set(rows) & set(obs))

    summary, diffs = [], []
    for col, (test, positive) in CHECKS.items():
        pairs = []
        for h in hosts:
            res = obs[h][test]['result']
            if col == 'cerez_tum_secure' and res == 'cookies-not-found':
                continue
            v = v1_value(rows[h], col)
            if v is None:
                continue
            o = positive(res)
            pairs.append((v, o))
            if v != o:
                diffs.append({'kontrol': col, 'alan_adi': h, 'v1': int(v), 'observatory': int(o), 'observatory_sonuc': res,
                              'observatory_veri': str(obs[h][test].get('data'))[:300]})
        po, k = kappa(pairs)
        summary.append({'kontrol': col, 'n': len(pairs), 'ikisi_de': sum(1 for x, y in pairs if x and y),
                        'yalniz_v1': sum(1 for x, y in pairs if x and not y), 'yalniz_observatory': sum(1 for x, y in pairs if y and not x),
                        'ikisi_de_degil': sum(1 for x, y in pairs if not x and not y), 'uyum': f'{po:.3f}', 'kappa': f'{k:.3f}'})

    a.dest.mkdir(parents=True, exist_ok=True)
    for name, data in (('dogrulama_observatory_ozet.csv', summary), ('dogrulama_observatory_farklar.csv', diffs)):
        with open(a.dest / name, 'w', newline='', encoding='utf-8-sig') as f:
            w = csv.DictWriter(f, fieldnames=list(data[0].keys()))
            w.writeheader()
            w.writerows(data)
    print(f'{len(hosts)} sites compared (Observatory failed on {len(set(rows) - set(obs))})')
    for s in summary:
        print(s)


if __name__ == '__main__':
    main()
