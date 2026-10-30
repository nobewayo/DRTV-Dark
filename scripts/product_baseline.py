"""Versioned accepted-source reference, shared by maintenance and release verification."""
if not __debug__:
    raise RuntimeError('Optimized Python is unsupported')
import copy
import json
from pathlib import Path
from product_common import ROOT, sha
from release_data import verify_signed

DIRECTORY = ROOT/'maintenance/4.39.0'


def load():
    value = json.loads((DIRECTORY/'baseline.json').read_bytes())
    assert value['schema'] == 1
    assert value['source'] == dict(package='dk.dr.tvplayer', versionName='4.39.0', versionCode=439000)
    assert value['acceptedSequence'] == 32
    assert sha((ROOT/'site/recipe.json').read_bytes()) == value['recipeSha256'], 'Accepted recipe changed'
    for name, digest in value['signedMaterial'].items():
        assert sha((DIRECTORY/name).read_bytes()) == digest, 'Accepted material changed: '+name
    trust = json.loads((DIRECTORY/'trust.json').read_bytes())
    release = verify_signed(DIRECTORY/'release.json', trust)
    updates = verify_signed(DIRECTORY/'updates.json', trust)
    assert release['themeCorrections']['totalSites'] == 121
    assert updates['sequence'] == 32 and updates['commonCertificate'] == trust['commonCertificate']
    assert updates['verification']['publicSigningSha256'] == sha((DIRECTORY/'release.json').read_bytes())
    return value, trust, release, updates


def construction_seed():
    """Reuse signed admission/payload/provider descriptors; never reuse target deltas.

    The first transaction is the original 110-site transformation plus authored
    provider injection. The maintained builder then constructs identity and the
    eleven extension sites from source, and compiles authored Java afresh.
    """
    value, trust, release, updates = load()
    seed = copy.deepcopy(release)
    for name in ('identity', 'themeCorrections', 'signatures', 'sourcePackage', 'signingProfile'):
        seed.pop(name, None)
    seed['package'] = value['source']['package']
    return seed, trust, updates
