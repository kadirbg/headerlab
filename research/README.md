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
| `scanner/` | Bulk scanner (coming next) |
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

## Running the tests

```sh
npm run test:research
```

Requires Node.js 22 or later (type stripping).

## Comparison with 2016

Variables ending in `_2016` reproduce the definitions of Kısa & Tatlı (2016),
*Analysis of HTTP Security Headers in Turkey*, and of their SecurityHeaderChecker
tool, so that 2016 and current rates are computed the same way. They are not this
study's own measure of correctness; see the comments in `criteria/headers-v1.ts`.

## Third-party data

`src/lib/csp-bypass-hosts.ts` contains URL lists copied from Google's
[CSP Evaluator](https://github.com/google/csp-evaluator) (Apache License 2.0); the
upstream commit and licence notice are in the file header.
