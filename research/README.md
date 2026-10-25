# research/

Measurement code for a study of HTTP security headers and Content Security Policy
(CSP) deployment on websites in Turkey: how widely the headers are used and whether
the CSP policies actually protect against script injection.

The website (`src/`) and this folder share one CSP parser (`src/lib/csp-evaluator.ts`)
and one list of known CSP bypass hosts (`src/lib/csp-bypass-hosts.ts`). Everything
else here is research-only and is not deployed.

## Layout

| Path | What it is |
| --- | --- |
| `criteria/csp-v1.ts` | CSP effectiveness classes and error flags H1–H9 |
| `criteria/headers-v1.ts` | Header validity rules, cookie variables, 2016-compatible variables |
| `tests/` | Unit tests. `csp-v1.test.ts` starts with the reference examples of criteria set v1 |
| `scanner/scan.ts` | Bulk scanner: raw redirect chains and headers → `scan.jsonl` |
| `scanner/classify.ts` | `scan.jsonl` → `main.csv` / `sub.csv`, coded with criteria set v1 |
| `scanner/seal.ts` | RFC 3161 timestamp for `scan.jsonl` (no openssl needed) |
| `data/`, `output/` | Site lists, raw scans and results. **Git-ignored; never committed** |

## Criteria version

`criteria/` implements **criteria set v1 (ölçüt seti v1)**, frozen on 2026-10-17
before any data was collected. Every later change is listed below with its date
and reason.

The study reports these rule-based classes, **not** HeaderLab's A–F grade.

### Criteria changelog

| Date | Change | Reason |
| --- | --- | --- |
| 2026-10-17 | v1 frozen | Before data collection |
| 2026-10-19 | C1: under `'strict-dynamic'`, `data:` does not trigger H3 | Browsers ignore scheme sources under `'strict-dynamic'`; v1 already said so for `*`, `https:`, `http:` and risky hosts |
| 2026-10-19 | C2: a script policy of exactly `'none'` meets the "nonce or hash" condition of the *etkili* class | No script can run under it |
| 2026-10-25 | C3: access classes `ok` / `engellendi` (400, 403, 406, 429 or a bot challenge) / `ulasilamadi` (no response) / `hata`; only `ok` pages are coded, protection is never bypassed | Pilot: bot challenges answered with the protection service's own headers |
| 2026-10-25 | C4: `alan_disi` flags a page whose final URL is outside the site's registrable domain; such subdomains are left out of subdomain-layer rates | Pilot: a subdomain redirected to another domain |
| 2026-10-25 | C5: after the main run, sites whose main access was not `ok`, that had a network-level error on a subdomain, or that were redirected to an ISP filter page are measured once more (`--only-file`); the second measurement is final (`classify --merge`) | Main run: resolver failures for about 10 minutes |
| 2026-10-25 | Scanner sends Chrome's navigation request headers (`Sec-Fetch-*`, `Upgrade-Insecure-Requests`); the User-Agent still names the scanner | Measure what a visitor receives |

## Running the tests

```sh
npm run test:research
```

Requires Node.js 22 or later (type stripping).

## Scanning

Run on a machine with a Turkish internet connection (not a corporate network,
not a cloud host): the study measures what a visitor in Turkey receives.

```sh
npm ci
# pilot: first 20 sites of the sample
npm run scan -- --input research/data/sample/orneklem_v1.csv --run pilot-1 --limit 20
npm run classify -- --run pilot-1
```

- Output goes to `research/output/<run>/`: `scan.jsonl` (raw), `manifest.json`
  (parameters, tool commit, input and output hashes), `main.csv`, `sub.csv`.
- Interrupted runs resume: run the same command again; finished sites are skipped.
- `--only a.com.tr,b.com` or `--only-file list.txt` scans selected sites; `--concurrency`, `--gap`,
  `--timeout`, `--max-subdomains` change the defaults (4, 2000 ms, 15000 ms, 10).
- Domains listed one per line in `research/data/opt-out.txt` are never scanned.
- Set the Chrome version in `--ua` (or `DEFAULT_UA` in `scan.ts`) to the one
  installed on the scanning machine.

Re-measurement (rule C5): scan the listed sites into a new run, then classify
the main run with the new one merged in; each row's `olcum` column names its run.

```sh
npm run scan -- --run ana-1b --only-file research/data/tekrar_ana-1.txt
npm run classify -- --run ana-1 --merge ana-1b    # → main-merged.csv, sub-merged.csv
```

Behaviour is described publicly at <https://headerlab.dev/research>.

### Sealing the raw data

Right after a run, timestamp `scan.jsonl` with an RFC 3161 TSA so it can later
be shown that the data was not changed after collection. `seal.ts` needs only
Node.js (default TSA: FreeTSA; any RFC 3161 TSA works via `--tsa`):

```sh
npm run seal -- --run <run>
```

It writes `scan.tsq` (request) and `scan.tsr` (signed response), checks that the
response carries the file's hash and the request's nonce, and records the time in
`manifest.json`. Verify the signature later on any machine with openssl
(`cacert.pem` and `tsa.crt` from the TSA's website):

```sh
cd research/output/<run>
openssl ts -reply -in scan.tsr -text          # shows the time and the hash
openssl ts -verify -data scan.jsonl -in scan.tsr -CAfile cacert.pem -untrusted tsa.crt
```

Keep `scan.jsonl`, `scan.tsq`, `scan.tsr` and `manifest.json` together.

## Comparison with 2016

Variables ending in `_2016` reproduce the definitions of Kısa & Tatlı (2016),
*Analysis of HTTP Security Headers in Turkey*, and of their SecurityHeaderChecker
tool, so that 2016 and current rates are computed the same way. They are not this
study's own measure of correctness; see the comments in `criteria/headers-v1.ts`.

## Third-party data

`src/lib/csp-bypass-hosts.ts` contains URL lists copied from Google's
[CSP Evaluator](https://github.com/google/csp-evaluator) (Apache License 2.0); the
upstream commit and licence notice are in the file header.
