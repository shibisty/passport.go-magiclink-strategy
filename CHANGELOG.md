# Changelog

## Unreleased

### Changed
- Renamed from `passport-magiclink` to `@passport/magiclink` (gtr ADR-0012): `gtr add @passport/magiclink`, `import "passport/magiclink"`; published to the gtr registry. Dependencies on other passport packages are registry ranges (`^0.2`) instead of `github:` sources.

## 0.1.1 — 2026-11-09

### Changed
- Requires `passport ^0.2` (the first published release of the core; `^0.1` matched no tag).

### Added
- The `passport-magiclink` package.
