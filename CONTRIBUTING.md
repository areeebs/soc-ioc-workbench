# Contributing

- Use Python 3.10 or newer and the standard library.
- Run `python3 -m unittest discover -s tests -v` before proposing a change.
- Keep tests offline; mock DNS and all provider HTTP responses.
- Add a regression test for parser, provider, privacy, or error-handling changes.
- Keep lookups explicit and single-provider. Do not add upload, scanning, or fan-out behavior without a documented use case and a new privacy review.
- Never commit API keys, real customer indicators, private case notes, or unredacted provider responses.

For a bug report, include a synthetic IOC and a sanitized expected/actual result.
