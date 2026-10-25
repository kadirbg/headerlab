"""Analysis of the classified scan results (criteria set v1).

Usage:
    python3 research/analysis/analyze.py --main <main-merged.csv> --sub <sub-merged.csv> --out <dir>

Writes CSV tables and ozet.md (a plain summary) to --out. Needs pandas, numpy, scipy.

Methods
- Proportions with Wilson 95% confidence intervals.
- Sector differences: chi-square test of independence on sector x outcome;
  p-value by Monte Carlo (fixed margins, 20 000 draws, fixed seed) because
  several sectors are small; effect size Cramer's V; Holm correction across
  the metrics tested.
- Comparison with Kisa & Tatli (2016): two-proportion z-test against the
  published rate and denominator, Holm correction across comparisons. Rates
  are computed with the *_2016 variables, which reproduce that study's
  definitions.
"""

import argparse
import math
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats

SEED = 20261025
MC_DRAWS = 20_000
SECTORS = ['KAMU', 'KRITIK', 'FINANS', 'EGITIM', 'ETICARET', 'MEDYA', 'INTERNET', 'DIGER']

# metric -> (label, denominator filter column or None)
MAIN_METRICS = {
    'https_erisilir': ('HTTPS erişilebilir', None),
    'http_https_yonlenir': ('HTTP→HTTPS yönlendirme', None),
    'hsts_var': ('HSTS var', None),
    'hsts_dogru': ('HSTS doğru (≥6 ay)', None),
    'hsts_guclu': ('HSTS güçlü (≥1 yıl + includeSubDomains)', None),
    'hsts_preload': ('HSTS preload direktifi', None),
    'clickjacking_korumasi': ('Clickjacking koruması (XFO veya frame-ancestors)', None),
    'xcto_dogru': ('X-Content-Type-Options: nosniff', None),
    'referrer_dogru': ('Referrer-Policy güvenli', None),
    'permissions_var': ('Permissions-Policy var', None),
    'coop_var': ('COOP var', None),
    'corp_var': ('CORP var', None),
    'csp_var': ('CSP var (başlık veya meta)', None),
    'csp_koruyucu': ('CSP XSS\'e karşı en az kısmen etkili', None),
    'xxss_var': ('X-XSS-Protection var (eskimiş)', None),
    'cerez_tum_secure': ('Çerezlerin tümü Secure', 'cerez_var'),
    'cerez_tum_httponly': ('Çerezlerin tümü HttpOnly', 'cerez_var'),
    'cerez_tum_samesite': ('Çerezlerin tümü SameSite', 'cerez_var'),
    'hic_baslik_yok_2016': ('Hiç güvenlik başlığı yok (2016 tanımı)', None),
}

CSP_ORDER = ['yok', 'uygulanmiyor', 'xss_kapsami_yok', 'atlatilabilir', 'kismen_etkili', 'etkili']
FLAGS = [f'H{i}' for i in range(1, 10)]

# Kisa & Tatli (2016). n is the published denominator; k is the published count,
# or round(rate * n) where only a percentage was published (approx=True).
BASE_2016 = [
    # key, label, our layer, our column, k, n, approx
    ('csp', 'CSP başlığı var', 'ana', 'csp_baslik_var', 21, 361, False),
    ('xxss', 'X-XSS-Protection var', 'ana', 'xxss_var', round(0.19 * 361), 361, True),
    ('hic', 'Hiç güvenlik başlığı yok', 'tum', 'hic_baslik_yok_2016', 465, 1274, False),
    ('xfo', 'X-Frame-Options var', 'tum', 'xfo_var', 153, 1274, False),
    ('xcto', 'X-Content-Type-Options var', 'tum', 'xcto_var', round(0.07 * 1274), 1274, True),
    ('hsts', 'HSTS var (HTTPS kullananlarda)', 'tum_https', 'hsts_var', round(0.21 * 287), 287, True),
]


def wilson(k: int, n: int, z: float = 1.959964) -> tuple[float, float]:
    if n == 0:
        return (math.nan, math.nan)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def holm(ps: list[float]) -> list[float]:
    m = len(ps)
    order = sorted(range(m), key=lambda i: ps[i])
    adj = [0.0] * m
    running = 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (m - rank) * ps[i]))
        adj[i] = running
    return adj


def chi2_mc(groups: np.ndarray, outcome: np.ndarray, rng: np.random.Generator) -> tuple[float, float, float, float]:
    """Chi-square statistic, asymptotic p, Monte Carlo p and Cramer's V for two categorical arrays."""
    g_codes, _ = pd.factorize(groups)
    o_codes, _ = pd.factorize(outcome)
    r, c = g_codes.max() + 1, o_codes.max() + 1
    table = np.zeros((r, c))
    np.add.at(table, (g_codes, o_codes), 1)
    if r < 2 or c < 2:
        return (math.nan, math.nan, math.nan, math.nan)
    chi2, p_asym, _, _ = stats.chi2_contingency(table, correction=False)
    exp = np.outer(table.sum(1), table.sum(0)) / table.sum()
    hits = 0
    for _ in range(MC_DRAWS):
        t = np.zeros((r, c))
        np.add.at(t, (g_codes, rng.permutation(o_codes)), 1)
        if (((t - exp) ** 2) / exp).sum() >= chi2 - 1e-9:
            hits += 1
    p_mc = (hits + 1) / (MC_DRAWS + 1)
    v = math.sqrt(chi2 / (table.sum() * (min(table.shape) - 1)))
    return (chi2, p_asym, p_mc, v)


def to_bool(s: pd.Series) -> pd.Series:
    return s.map({'1': True, '0': False, 1: True, 0: False, True: True, False: False})


def load(main_path: Path, sub_path: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    main = pd.read_csv(main_path, dtype=str, keep_default_na=False, encoding='utf-8-sig')
    sub = pd.read_csv(sub_path, dtype=str, keep_default_na=False, encoding='utf-8-sig')
    return main, sub


def prepare(df: pd.DataFrame) -> pd.DataFrame:
    ok = df[df['erisim'] == 'ok'].copy()
    ok['cerez_var'] = ok['cerez_sayisi'].replace('', '0').astype(int) > 0
    ok['csp_koruyucu'] = ok['csp_sinif'].isin(['kismen_etkili', 'etkili']).map({True: '1', False: '0'})
    return ok


def rate(df: pd.DataFrame, col: str, filt: str | None) -> tuple[int, int]:
    if col not in df.columns:
        return 0, 0
    d = df[df[filt]] if filt else df
    v = to_bool(d[col])
    v = v.dropna()
    return int(v.sum()), int(len(v))


def fmt_pct(k: int, n: int) -> str:
    if n == 0:
        return '–'
    lo, hi = wilson(k, n)
    return f'{100 * k / n:.1f} [{100 * lo:.1f}–{100 * hi:.1f}]'


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--main', required=True, type=Path)
    ap.add_argument('--sub', required=True, type=Path)
    ap.add_argument('--out', required=True, type=Path)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(SEED)

    main_all, sub_all = load(a.main, a.sub)
    md: list[str] = ['# Analiz özeti (ölçüt seti v1)', '']

    # 1. Access
    acc = pd.crosstab(main_all['sektor'], main_all['erisim']).reindex(SECTORS).fillna(0).astype(int)
    acc['toplam'] = acc.sum(axis=1)
    acc.loc['TOPLAM'] = acc.sum()
    acc.to_csv(a.out / 'erisim_sektor.csv', encoding='utf-8-sig')
    md += ['## 1. Erişim (ana katman)', '', acc.to_markdown(), '']
    sub_acc = sub_all.assign(katman=np.where(sub_all['alan_disi'] == '1', 'alan_disi', sub_all['erisim']))['katman'].value_counts()
    md += [f'Alt alan katmanı: {len(sub_all)} alt alan; ' + ', '.join(f'{k} {v}' for k, v in sub_acc.items()) + '.', '']

    ana = prepare(main_all)
    alt = prepare(sub_all[sub_all['alan_disi'] != '1'])
    md += [f'Analiz: ana katmanda {len(ana)} site, alt alan katmanında {len(alt)} alt alan (alan dışına yönlenenler hariç).', '']

    # 2. Rates by sector, main layer
    rows = []
    for col, (label, filt) in MAIN_METRICS.items():
        k, n = rate(ana, col, filt)
        row = {'metrik': col, 'etiket': label, 'k': k, 'n': n, 'yuzde_GA': fmt_pct(k, n)}
        for s in SECTORS:
            ks, ns = rate(ana[ana['sektor'] == s], col, filt)
            row[s] = fmt_pct(ks, ns)
            row[f'{s}_n'] = ns
        ks, ns = rate(alt, col, filt)
        row['alt_alan'] = fmt_pct(ks, ns)
        row['alt_alan_n'] = ns
        rows.append(row)
    rates = pd.DataFrame(rows)
    rates.to_csv(a.out / 'oranlar_sektor.csv', index=False, encoding='utf-8-sig')
    show = rates[['etiket', 'k', 'n', 'yuzde_GA'] + SECTORS + ['alt_alan']]
    md += ['## 2. Oranlar (ana katman, % [Wilson %95 GA])', '', show.to_markdown(index=False), '',
           'Sektör sütunlarının paydaları `oranlar_sektor.csv` içinde (`<SEKTOR>_n`). Çerez satırlarının paydası çerez kuran sitelerdir.', '']

    # 3. Sector differences
    tests = []
    for col, (label, filt) in MAIN_METRICS.items():
        d = ana[ana[filt]] if filt else ana
        v = to_bool(d[col])
        keep = v.notna()
        chi2, p_asym, p_mc, cv = chi2_mc(d.loc[keep, 'sektor'].to_numpy(), v[keep].astype(int).to_numpy(), rng)
        tests.append({'metrik': col, 'etiket': label, 'n': int(keep.sum()), 'chi2': chi2, 'sd': 7, 'p_asimptotik': p_asym, 'p_monte_carlo': p_mc, 'cramer_v': cv})
    tdf = pd.DataFrame(tests)
    valid = tdf['p_monte_carlo'].notna()
    tdf.loc[valid, 'p_holm'] = holm(tdf.loc[valid, 'p_monte_carlo'].tolist())
    tdf.to_csv(a.out / 'sektor_farki_testleri.csv', index=False, encoding='utf-8-sig')
    md += ['## 3. Sektörler arası fark (ki-kare, Monte Carlo p, Holm)', '',
           tdf.assign(**{c: tdf[c].map(lambda x: '<0.0001' if x < 0.0001 else f'{x:.4f}') for c in ['p_monte_carlo', 'p_holm']}, cramer_v=tdf['cramer_v'].map(lambda x: f'{x:.3f}'), chi2=tdf['chi2'].map(lambda x: f'{x:.2f}'))[['etiket', 'n', 'chi2', 'p_monte_carlo', 'p_holm', 'cramer_v']].to_markdown(index=False), '']

    # 4. CSP classes and flags
    cls = pd.crosstab(ana['sektor'], ana['csp_sinif']).reindex(index=SECTORS, columns=CSP_ORDER).fillna(0).astype(int)
    cls.loc['TOPLAM'] = cls.sum()
    cls['toplam'] = cls.sum(axis=1)
    cls.to_csv(a.out / 'csp_sinif_sektor.csv', encoding='utf-8-sig')
    csp_sites = ana[ana['csp_sinif'] != 'yok']
    flag_rows = []
    for f in FLAGS:
        k = int(to_bool(csp_sites[f'csp_{f}']).sum())
        flag_rows.append({'bayrak': f, 'k': k, 'n': len(csp_sites), 'yuzde_GA': fmt_pct(k, len(csp_sites))})
    flags = pd.DataFrame(flag_rows)
    flags.to_csv(a.out / 'csp_bayraklar.csv', index=False, encoding='utf-8-sig')
    src = csp_sites['csp_kaynak'].replace('', '(yalnız Report-Only)').value_counts()
    md += ['## 4. CSP sınıfları (ana katman)', '', cls.to_markdown(), '',
           f'CSP\'si olan {len(csp_sites)} sitede hata bayrakları (paydası bu siteler):', '', flags.to_markdown(index=False), '',
           'Uygulanan politikanın kaynağı: ' + ', '.join(f'{k} {v}' for k, v in src.items()) + '.', '']

    # 5. Comparison with 2016
    tum = pd.concat([ana, alt])
    layers = {'ana': ana, 'tum': tum, 'tum_https': tum[to_bool(tum['https']) == True]}  # noqa: E712
    comp = []
    for key, label, layer, col, k16, n16, approx in BASE_2016:
        d = layers[layer]
        v = to_bool(d[col]).dropna()
        k, n = int(v.sum()), int(len(v))
        p1, p2 = k16 / n16, k / n
        pool = (k16 + k) / (n16 + n)
        z = (p2 - p1) / math.sqrt(pool * (1 - pool) * (1 / n16 + 1 / n))
        p = 2 * stats.norm.sf(abs(z))
        comp.append({'karsilastirma': label, 'katman_2026': layer, 'oran_2016': f'{100 * p1:.1f} ({k16}/{n16}{", yaklaşık" if approx else ""})',
                     'oran_2026': f'{100 * p2:.1f} ({k}/{n})', 'fark_puan': round(100 * (p2 - p1), 1), 'z': round(z, 2), 'p': p})
    cdf = pd.DataFrame(comp)
    cdf['p_holm'] = holm(cdf['p'].tolist())
    cdf.to_csv(a.out / 'karsilastirma_2016.csv', index=False, encoding='utf-8-sig')
    md += ['## 5. Kısa ve Tatlı (2016) ile karşılaştırma (iki oran z testi, Holm)', '',
           cdf.assign(p=cdf['p'].map(lambda x: f'{x:.2e}'), p_holm=cdf['p_holm'].map(lambda x: f'{x:.2e}')).to_markdown(index=False), '',
           'Katmanlar: `ana` = ana sayfalar (2016\'nın 361 portal paydasına karşılık), `tum` = ana sayfa + bağlantılı alt alanlar '
           '(2016\'nın 1 274 alt alan paydasına karşılık), `tum_https` = bunlardan HTTPS sunanlar. '
           '"yaklaşık" işaretli 2016 sayıları yayımlanan yüzdeden geri hesaplanmıştır.', '']

    # 6. Sensitivity: HSTS read from the final response (MDN Observatory's rule)
    if 'hsts_son_var' in ana.columns:
        sens = []
        for base, alt_col, label in (('hsts_var', 'hsts_son_var', 'HSTS var'), ('hsts_dogru', 'hsts_son_dogru', 'HSTS doğru (≥6 ay)'), ('hsts_guclu', 'hsts_son_guclu', 'HSTS güçlü')):
            for layer_name, d in (('ana', ana), ('alt_alan', alt)):
                x = to_bool(d[base]).fillna(False).to_numpy(bool)
                y = to_bool(d[alt_col]).fillna(False).to_numpy(bool)
                b, c = int((x & ~y).sum()), int((~x & y).sum())
                p = stats.binomtest(min(b, c), b + c, 0.5).pvalue if b + c else 1.0
                sens.append({'olcu': label, 'katman': layer_name, 'n': len(d), 'v1_ilk_https_yanit': fmt_pct(int(x.sum()), len(d)),
                             'son_yanit': fmt_pct(int(y.sum()), len(d)), 'yalniz_v1': b, 'yalniz_son': c, 'p_mcnemar_kesin': p})
        sdf = pd.DataFrame(sens)
        sdf.to_csv(a.out / 'duyarlilik_hsts.csv', index=False, encoding='utf-8-sig')
        md += ['## 6. Duyarlılık: HSTS\'nin okunduğu yanıt', '',
               'v1, HSTS\'yi `https://<alan>/` isteğinin ilk HTTPS yanıtından okur (kullanıcının alan adını yazdığı ilk bağlantı). '
               'MDN HTTP Observatory son yanıtı kullanır. Aynı siteler iki tanımla kodlandı; fark kesin McNemar testiyle sınandı.', '',
               sdf.assign(p_mcnemar_kesin=sdf['p_mcnemar_kesin'].map(lambda x: '<0.0001' if x < 0.0001 else f'{x:.4f}')).to_markdown(index=False), '']

    (a.out / 'ozet.md').write_text('\n'.join(md), encoding='utf-8')
    print(f'wrote {a.out}/ozet.md and tables; main ok {len(ana)}, sub ok {len(alt)}')


if __name__ == '__main__':
    main()
