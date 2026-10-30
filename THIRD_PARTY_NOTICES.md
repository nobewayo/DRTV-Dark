# Dependency and rights inventory

DRTV Dark's authored code (website engine, build/signing/verification tools, theme
recipe tooling and the native Update Manager sources) is Copyright (C) 2026 the DRTV Dark
authors and licensed under the GNU General Public License, version 3 or (at your option)
any later version (`GPL-3.0-or-later`); the full text is in `LICENSE`. Third-party
components below keep their own licenses. No license for DR's application, programme
images or branding is granted here. APKs and proprietary
disassembly are not distributed. Genuine approved comparison/guide images and their
existing provenance are preserved; this task makes no new rights assertion.

| Component | Role/version | Notice and provenance |
|---|---|---|
| Schibsted Grotesk | Bundled website font, Latin/Latin-ext | Full SIL OFL: `site/fonts/OFL.txt` |
| bsdiff4 | Offline delta generator, 1.2.6 | Full installed compound notice: `LICENSES/bsdiff4-LICENSE.txt`; Ilan Schnell and cx_bsdiff/Anthony Tuininga notices must remain complete |
| BSDIFF40 | Algorithm/format lineage only, no browser bsdiff dependency | Colin Percival, [original project](https://www.daemonology.net/bsdiff/) |
| smali-dexlib2 | External SDK offline tool, 3.0.9 | Full embedded upstream notice: `LICENSES/dexlib-LICENSE.txt`; no JAR bundled |
| Guava | External offline dependency, 33.4.0-jre | Full embedded Apache notice: `LICENSES/guava-LICENSE.txt` |
| failureaccess | External offline dependency, 1.0.2 | Apache-2.0 inherited from its [guava-parent 26.0-android POM](https://repo.maven.apache.org/maven2/com/google/guava/guava-parent/26.0-android/guava-parent-26.0-android.pom); full text `LICENSES/Apache-2.0.txt` |
| jsr305 | External offline dependency, 3.0.2 | Apache-2.0 declared by the [exact release POM](https://repo.maven.apache.org/maven2/com/google/code/findbugs/jsr305/3.0.2/jsr305-3.0.2.pom); full text `LICENSES/Apache-2.0.txt` |
| cryptography | External Python signing/verification, 50.0.2 | Installed metadata: Apache-2.0 OR BSD-3-Clause; [upstream notices](https://github.com/pyca/cryptography/tree/50.0.2/licenses); package binary/source not redistributed |
| Python, Node, JDK, Android SDK, Apktool | External build/inspection tools | Install separately under their own licenses; no binaries bundled. SDK/JDK are not website dependencies |
| Official GitHub checkout/upload-pages-artifact/deploy-pages actions | Future manual CI, pinned revisions in YAML | [Official actions](https://github.com/actions); no action source vendored |

The browser engine uses authored JavaScript plus browser platform APIs; it does not
download bsdiff, cryptography, a signing key or an APK payload from this site. Retaining
notices is not a legal opinion; the listed permissive licenses are generally regarded as
compatible with GPL-3.0-or-later for the authored code. Recheck this
inventory when adding/redistributing dependencies; do not collapse the bsdiff4 compound
license into a generic BSD label.
