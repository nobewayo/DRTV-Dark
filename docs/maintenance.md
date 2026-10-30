# Maintained product workflow

`scripts/maintain.py` is the stable entry point. Inspection, comparison, candidate
construction, verification, source export and publication verification are separate
operations. None stages Git files, changes history, uploads or deploys.

```fish
python3 -B scripts/maintain.py inspect --candidate NEW_BASE_APK --out work/inspect.json
python3 -B scripts/maintain.py compare --previous ACCEPTED_ORIGINAL_BASE --candidate NEW_BASE_APK --out work/compare.json
python3 -B scripts/maintain.py candidate --mode rehearsal --original-dir ORIGINALS --out work/rehearsal
python3 -B scripts/maintain.py verify --release work/rehearsal/release --original-dir ORIGINALS
python3 -B scripts/maintain.py export --out work/public-source
```

Inspection records APK signature verification and manifest identity without admitting
the file. Comparison requires the exact last supported official base APK. JSON and
Markdown reports distinguish unchanged owners, unique byte-identical relocated
candidates, modified/ambiguous owners and missing owners. Only a completely identical
owner qualifies as unchanged. Even a unique relocated file needs ownership review.
Changed paths, colors, strings or partially matching methods are never accepted as
equivalence. Candidate input is bounded and read without extraction or execution.

`maintenance/4.39.0/theme-sites.json` records all 121 accepted theme sites. Each site
points to its exact descriptor in `site/recipe.json` (110) or the accepted signed
`maintenance/4.39.0/release.json` (11), with a descriptor digest. It records the original
owner hash, resource configuration and original values, XML element context, or full
DEX method signature and instruction digest. The descriptor remains the canonical
intended transformation. Selector references for the dialog retain foreground and
background state relationships; Java theme hooks retain runtime component ownership.
Existing authenticated site IDs remain stable for provenance.

The structural scan flags newly bright static background/window attributes and named
background colors. Changed content/artwork is listed separately and never recolored.
Malformed/unsupported resource structures require manual inspection. This conservative
scan cannot identify server-loaded content or all runtime-created UI. In particular,
the known white children's banner remains deferred; it is not silently fixed here.

For a real future official source:

1. Inspect its signatures, package, manifest, version and split variants; retain exact
   input hashes privately. Compare to the accepted original. No report grants admission.
2. Review every changed/relocated/missing owner and new bright structural candidate.
   Validate foreground/background and shared-component effects. Preserve artwork.
3. Create a new versioned maintenance baseline. Deliberately update exact admission,
   source-relative selectors, bounded transformations and expected payload verification.
   The existing 4.39.0 baseline stays recoverable. There is no automatic migration writer.
4. Build with disposable identities and verify authenticated site coverage and
   unrelated-payload preservation. Update focused fixtures for the actual new source.
   The current builder intentionally refuses other source versions until these changes
   have been implemented and reviewed; editing release facts alone never suffices.
5. Separately complete the required product acceptance, authorize production signing
   using the same two permanent identities and a higher sequence, construct the compatible
   schema6 upgrade path, export, review and verify the exact publication artifact.

The browser patch engine, identity delta decoder and signing adapter are shared with
offline construction. Do not replace them with an alternative engine or metadata signer.
Host Java helpers inspect/transform exact owners; their outputs feed authenticated
source-relative material, not redistributed proprietary APK payloads.
