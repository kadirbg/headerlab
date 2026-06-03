# HeaderLab

Modern web security toolkit — free, fast, privacy-first tools for developers and the security community.

**Live:** [headerlab.dev](https://headerlab.dev)

## Tools

- **[HTTP Security Headers Checker](https://headerlab.dev/headers)** — Inspect any URL for missing/misconfigured security headers. Severity-ranked findings with copyable fix snippets for Nginx, Apache, and Cloudflare.
- **[CSP Builder](https://headerlab.dev/csp)** — Build a strict Content Security Policy with a visual editor. 11 directives, 4 templates (Strict/Balanced/Permissive/Empty), live preview.
- **[CSP Evaluator](https://headerlab.dev/csp-evaluator)** — Audit any Content Security Policy for weaknesses, missing directives, and known bypass patterns. 15+ weakness checks across severity tiers.
- **[JWT Decoder](https://headerlab.dev/jwt)** — Decode JSON Web Tokens and analyze them for security pitfalls (`alg=none`, missing expiry, excessive lifetime, sensitive data in payload).

## What's different

- **Privacy-first.** No accounts, no tracking, no stored URLs. Cookieless aggregate analytics only.
- **Open source.** MIT-licensed. Read the engines, fork the project, contribute.
- **No ads, no trackers.** Tools run client-side when possible. URLs sent to the server are processed in real-time and discarded.
- **Honest scoring.** HeaderLab does not scan its own domain — see [methodology](https://headerlab.dev/methodology) for the reasoning.

## Stack

- [Astro](https://astro.build/) — static-first, server-rendered API routes
- TypeScript (strict)
- [Cloudflare Workers](https://workers.cloudflare.com/) hosting
- Zero runtime dependencies for the analysis engines (`src/lib/`)

## Local development

```bash
git clone https://github.com/kadirbg/headerlab.git
cd headerlab
npm install
npm run dev
```

Opens at `http://localhost:4321`.

## Documentation

- [About](https://headerlab.dev/about) — project background and principles
- [Methodology](https://headerlab.dev/methodology) — how scoring works, with weights and rationale
- [Privacy Policy](https://headerlab.dev/privacy)

## Contributing

Issues and pull requests welcome. For larger changes, please [open an issue](https://github.com/kadirbg/headerlab/issues) first to discuss the direction.

## License

MIT — see [LICENSE](./LICENSE).
