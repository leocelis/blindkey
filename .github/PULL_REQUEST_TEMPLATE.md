<!-- Thanks for contributing to Blindkey! Security tool → high bar. See CONTRIBUTING.md. -->

## What does this change?

<!-- A clear description of the change and why. -->

## Affected constraints

<!-- List the constraint IDs this touches, e.g. C7, C10. New behavior with no constraint? Open a
     discussion first so we add the constraint (with a test) before implementation. -->

- Constraints:
- New constraint added? (Y/N):

## Checklist

- [ ] `just check` passes (fmt, clippy `-D warnings`, tests)
- [ ] `just audit` passes (no new advisories / license violations / unvetted deps)
- [ ] New/changed behavior has a test that maps to a constraint
- [ ] No secret material can reach a log, `Debug`, default stdout, or argv
- [ ] No `unsafe` outside the reviewed crypto-FFI module; no custom crypto
- [ ] Conventional Commit messages
- [ ] I agree to license my contribution under MIT OR Apache-2.0

## Security impact

<!-- Does this change the threat surface? If unsure, say so and tag a maintainer. -->
