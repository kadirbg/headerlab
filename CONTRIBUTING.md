# Contributing to HeaderLab

Thanks for your interest in contributing!

## Reporting bugs

Open a [GitHub issue](https://github.com/kadirbg/headerlab/issues/new/choose). Include:

- What you tried
- What you expected to happen
- What actually happened
- Browser + OS
- URL or tool affected

## Suggesting features

Open an issue with the **enhancement** label. Tell us:

- The problem you're trying to solve
- Why existing tools don't fit
- Your proposed approach (if you have one)

## Pull requests

1. Fork the repo
2. Create a feature branch (`feat/your-thing` or `fix/your-thing`)
3. Make your change
4. Run `npm run build` to verify it compiles
5. Open a PR with a clear description of what changed and why

For larger changes, please open an issue first so we can discuss the direction before you invest time.

## Code style

- TypeScript strict mode
- 2-space indentation, single quotes
- No runtime dependencies in `src/lib/` — the analysis engines must stay zero-dep so they can be embedded anywhere

## Out of scope

We're focused on **HTTP-layer web security tools**. Suggestions for password managers, certificate scanners, or pen-testing tools are interesting but out of scope. Use the [issue tracker](https://github.com/kadirbg/headerlab/issues) to discuss if you're not sure.
