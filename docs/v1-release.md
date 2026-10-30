# DRTV Dark version 1: release record

## Release facts

| Fact | Value |
|---|---|
| DRTV Dark version | `1`, sequence `32`, minInstalledSequence `32`, date 2026-10-29 |
| Supported original | `dk.dr.tvplayer` 4.39.0 / versionCode 439000 only |
| Installed application | `io.github.nobewayo.drtvdark`, alongside official DR TV |
| Website | `https://nobewayo.github.io/DRTV-Dark/` |
| Native update endpoint | `https://nobewayo.github.io/DRTV-Dark/updates.json` |
| Theme | 121 verified sites, dark charcoal launcher icon |
| Metadata | Signed schema6, `expiresAt:""` (no periodic re-signing) |
| Release data | [`releases/drtv-dark-v1.json`](../releases/drtv-dark-v1.json) |

No earlier production installation exists, so the schema6 `upgrade.from` list is empty.
Development or rehearsal DRTV Dark installations are signed by other keys and cannot be
upgraded in place to version 1.

## Permanent public identities

| Identity | Public fingerprint (SHA-256) |
|---|---|
| APK certificate (`CN=DRTV Dark`, RSA 3072) | `08493594bb8954cedb78c39171c15f7ef1d471e210b4f5483db46a4255dd3518` |
| Metadata key SPKI (RSA 3072) | `a42302d7252889428c8c278053f990a2842e63393b823e603663a64b33670625` |
| Public trust file (`trust.json`) | `0995a2afe867bac37aaa41af32238aca285df35bed10a972dbbbaab40c832ce6` |
| Version 1 package (`drtv-dark-v1.apks`) | `3f13206274e704661d790e28e3138a7b7a058f70826ce3ac3c859b7349d89f98` |
| Version 1 `base.apk` / `split_config.xhdpi.apk` | `fa87a4c605ecc61999827a309e8e93f35f828d5400eb0800206b493201a51a09` / `bc13c0f17488c7b4fcd21082a9322c7a5ad97d057648f6c8b37b1860c5e1aa0c` |

Check a downloaded package's signer with Android SDK build-tools:
`apksigner verify --print-certs base.apk` must print the APK certificate digest above.
The private keys exist only offline; they are never in this repository, the website or
GitHub Actions.

## Build and publication

The offline authorization for version 1 is
[`releases/drtv-dark-v1-authorization.json`](../releases/drtv-dark-v1-authorization.json);
the publication record is
[`releases/publication-approval.json`](../releases/publication-approval.json). It pins the
static website archive (`archiveSha256`), its inventory, both public identities, the
release facts and this repository's `EXPORT-MANIFEST.json`. Build commands, the
publication gate and the deployment workflow are described in
[`building.md`](building.md).
