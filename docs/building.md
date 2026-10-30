# Build and verify

The admitted original is DR TV 4.39.0 / 439000 only. Obtain the original APKs
separately and lawfully. This source project contains no original or modified APK,
private key, downloaded executable, or signing credential. The website performs
patching locally. Optional Smartago installation transfer uses Smartago's service.

## Dependencies

Use Python 3.12+, Node 24+, JDK 17+, Android SDK build-tools 35.0.0 and
platform android-35. Set `ANDROID_SDK_ROOT` to your SDK. Install the exact Python
packages in `requirements.txt` in an isolated environment:

```fish
python3 -m venv work/python
work/python/bin/python -m pip install -r requirements.txt
```

Supply `tools/apktool.jar` separately (used as a read-only dexlib
index dependency). Its SHA-256 must be
`dbf930b076c6b9be08d57c449cacefc3bdd6b71ebd59b3066fc0e1f5b14f9423`.
The exact JARs provided by Android SDK cmdline-tools under
`cmdline-tools/latest/lib/external/` are listed, with hashes, in
`releases/build-dependencies.json`: smali-dexlib2 3.0.9, Guava 33.4.0-jre,
failureaccess 1.0.2 and jsr305 3.0.2. The build checks all five JAR hashes and
compiles its own helpers. No precompiled project helper is required. See notices
for the external dependencies' licenses. No command proxy is required.

## Standalone rehearsal

Run from the source root, using a new ignored `work/` output directory:

```fish
work/python/bin/python -B scripts/maintain.py candidate --mode rehearsal --original-dir /PATH/TO/ORIGINALS --out work/rehearsal
```

The input directory must contain `base.apk` and `split_config.xhdpi.apk`.
Only exact signed, hash-pinned originals are admitted. The accepted signed public
reference and all build inputs are included under `maintenance/4.39.0/`.
Neither an older modified APK nor development signing material is needed.
The command generates two labelled disposable RSA3072 identities in a restricted
`private/` directory and builds `release/drtv-dark.apks`. It independently verifies
Android v2 signatures, alignment, application identity, all 121 authenticated theme
sites, signed schema6 metadata and every accepted APK payload. Only the embedded
release configuration varies with rehearsal facts and public identities. A second
browser-engine reconstruction must produce identical output with these same keys.
Different identities produce different signed bytes; this is no claim of production
APK byte equality. Test-key packages cannot update an existing production installation.

Focused tests (no device/browser sessions):

```fish
work/python/bin/python -B tests/theme_migration.py /PATH/TO/ORIGINALS/base.apk
env DRTV_RELEASE=work/rehearsal/release node --test tests/security.mjs
work/python/bin/python -B tests/candidate_security.py work/rehearsal/release work/rehearsal/private/profile.json
```

The rehearsal does not rebuild the website. For an independently authorized release,
`scripts/static_build.py` constructs the static website from public signed material.
The existing approved static archive is a separately retained, prebuilt release input.
Building source never uploads, publishes, deploys or approves it.

## Future production releases

See `maintenance.md` for source migration. A source comparison grants no support.
The accepted v1 and sequence 32 are immutable. The maintained production command
requires an increased sequence, the existing APK certificate and metadata trust key,
an external encrypted PKCS12 APK identity and encrypted PKCS8 metadata identity, and
an independently pinned offline authorization. It never generates production keys.
The profile schema is:

```json
{"schema":1,"mode":"production","apkContainer":"/OFFLINE/apk.p12","metadataKey":"/OFFLINE/metadata.pem","certificateSha256":"CERT_DER_SHA256","metadataSpkiSha256":"SPKI_DER_SHA256"}
```

Private files must be accessible only to their owner. Passwords are hidden prompts.
`scripts/signing.py --profile PROFILE --export-trust NEW_FILE` exports public trust.
`scripts/authorize.py` constructs the offline release authorization from approved
release facts, public trust and HTTPS addresses. After v1 it requires `--upgrade-from`
with a reviewed JSON list that explicitly includes v1's sequence/version/source identity.
After independent review and owner
authorization only:

```fish
work/python/bin/python -B scripts/maintain.py candidate --mode production --original-dir ORIGINALS --data RELEASE_DATA --profile PROFILE --approval AUTHORIZATION --approval-sha256 PIN --out work/authorized-candidate
```

No future official version is admitted by this command until the versioned source
configuration and transformations have been explicitly migrated and reviewed.
Compatible updates retain `io.github.nobewayo.drtvdark`, both signing identities and
the schema6 `upgrade.from` identity of installed v1, with a higher sequence and a
compatible `minInstalledSequence`. Neither uninstall nor resetting data is part of
that path. Keep the offline maximum-sequence ledger. A website rollback cannot lower
the native sequence floor. `expiresAt:""` avoids periodic renewal of unchanged metadata.
The optional `scripts/sign_metadata.py` command signs externally supplied schema6
data with the same adapter, requires a previous-sequence floor and verifies its output;
it never supplies production keys or deployment authorization.

## Publication integrity

`maintenance/public-files.json` defines the exact public source file set.
`EXPORT-MANIFEST.json` hashes every file except `releases/publication-approval.json`.
That record pins the manifest, approved prebuilt archive, static inventory, trust,
release facts and both public identities. Its exclusion avoids a hash cycle.
`scripts/approval_record.py` prepares the proposed record. Re-exporting after a record
update must leave the manifest unchanged. Source approval still requires independent
review and the owner's separate authorization to publish.

Verify the exact untouched source checkout and retained prebuilt ZIP together:

```fish
python3 -B scripts/publication.py --source CLEAN_SOURCE --archive static-candidate.zip --extract NEW_DIRECTORY --approval CLEAN_SOURCE/releases/publication-approval.json
```

The source gate rejects modified, missing or extra files, changed identities, a
different approval record and changed static bytes. Run it against a pristine source
copy: local dependencies and build output are intentionally extra files.
`tests/publication_integrity.py STATIC_ARCHIVE CLEAN_SOURCE` exercises the exact
archive/checkout pair and focused negative cases without keys or network access.
The manual GitHub Pages workflow runs the same gate on its own exact checkout.
Only a manual dispatch can request deployment; the `owner-approved-pages` environment
must have required owner reviewers and protected refs configured separately. Protect
the workflow and approval record through branch rules. Ordinary commits never deploy.
Keys, APKs and build output never enter Actions. The owner separately authorizes
uploading the unchanged static ZIP as a release asset. No GitHub configuration or
action is performed by these tools.
