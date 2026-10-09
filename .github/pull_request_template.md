## Summary

<!-- One paragraph: what changes and why. -->

## Evidence

<!-- Commands run with real counts: pytest results, link checks, build output. -->

- Tests: `python -m pytest tests -q` →
- Docs links verified:
- No source-behavior change: `git diff --stat -- src/` →

## Release impact

<!-- Does this touch version pins, release records, tags, or published artifacts? -->

- [ ] No version, tag, manifest, or checksum changes
- [ ] Changes release-adjacent files (justified above; no published artifact touched)

## Checklist

- [ ] English-only prose (test fixtures with multilingual payloads excepted and labeled)
- [ ] No secrets, credentials, or personal paths in diff or reports
- [ ] Honesty labels preserved (tested / environment-blocked / untested stay distinct)
