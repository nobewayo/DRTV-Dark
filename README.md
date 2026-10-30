# DRTV Dark

**Mørkt tema til DR TV på Android TV og Google TV.** DRTV Dark is a static website that
turns an exact, legitimately obtained copy of the DR TV Android TV app into a dark-themed,
independently installed app (`io.github.nobewayo.drtvdark`) that runs alongside the
official DR TV app. Patching happens entirely in your browser; your APK files are never
uploaded to DRTV Dark.

Website: <https://nobewayo.github.io/DRTV-Dark/>

DRTV Dark is an unofficial community project. It is not affiliated with, endorsed by or
supported by DR. DR TV, its content, images and marks belong to their owners; no license
to them is granted here, and no original or modified DR TV APK is distributed.

## What version 1 supports

* Original: DR TV `dk.dr.tvplayer` **4.39.0 / versionCode 439000 only**, from the two
  hash-pinned source variants. Any other file is rejected.
* Output: a split package (`.apks`) signed with the single DRTV Dark APK certificate,
  so later compatible DRTV Dark versions install over it without uninstalling.
* 121 verified dark-theme changes and a dark launcher icon.
* A native Update Manager (button beside `HJÆLP` on Home) that reads signed, maintenance-free
  metadata from `https://nobewayo.github.io/DRTV-Dark/updates.json`. It only informs; it
  never downloads or installs by itself.
* Installation to the TV via Smartago's Web Installer is optional and uses Smartago's own
  hosted service, outside DRTV Dark's control.

## How trust works

* The website admits only original files whose SHA-256 hashes and Android signatures match
  the signed release envelope.
* The browser rebuilds the modified APKs deterministically and attaches detached Android v2
  signature blocks made offline. They match only the exact expected bytes, so the site
  cannot sign anything else. The browser never holds a private key.
* Release and update metadata are signed by a separate offline metadata key. Public
  fingerprints are in [`docs/v1-release.md`](docs/v1-release.md).
* GitHub Pages serves only a prebuilt, audited static artifact through a manually approved
  workflow. No build, key or APK is present in GitHub Actions.

## Building and verifying

See [`docs/v1-release.md`](docs/v1-release.md) for the release record and verification
and [`docs/building.md`](docs/building.md) for requirements, the offline build with your
own signing identities and the publication gate. Proprietary inputs (the original APKs)
must be supplied by you and are never committed.

## License

DRTV Dark's authored code is licensed under the GNU General Public License v3.0 or later
(`GPL-3.0-or-later`); see [`LICENSE`](LICENSE). Third-party notices are in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) and [`LICENSES/`](LICENSES/).
