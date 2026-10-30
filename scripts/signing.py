"""External offline identities. No generation, discovery or development fallback."""
if not __debug__: raise RuntimeError('Optimized Python is unsupported for signing/theme validation')
import atexit
import base64
import getpass
import hashlib
import json
import os
import tempfile
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12

_loaded = None


def sha(b): return hashlib.sha256(b).hexdigest()


def load(path=None):
    global _loaded
    if _loaded is not None:
        selected=path or os.environ.get('DRTV_SIGNING_PROFILE')
        if selected:assert Path(selected).resolve()==_loaded['path'],'Signing profile cannot change in-process'
        return _loaded
    path = Path(path or os.environ['DRTV_SIGNING_PROFILE']).resolve()
    v = json.loads(path.read_text())
    assert set(v) == {'schema', 'mode', 'apkContainer', 'metadataKey', 'certificateSha256', 'metadataSpkiSha256'}
    assert v['schema'] == 1 and v['mode'] in ('rehearsal', 'production')
    def private(name):
        p = Path(v[name]); assert p.is_absolute() and p.is_file() and not p.is_symlink()
        assert p.stat().st_mode & 0o077 == 0, 'Private input permissions'
        return p.read_bytes()
    apk_raw = private('apkContainer'); meta_raw = private('metadataKey')
    # Rehearsal containers are disposable; production containers must be encrypted.
    password = None if v['mode'] == 'rehearsal' else getpass.getpass('APK container password: ').encode()
    apk, cert, extras = pkcs12.load_key_and_certificates(apk_raw, password)
    meta_password = None if v['mode'] == 'rehearsal' else getpass.getpass('Metadata key password: ').encode()
    metadata = serialization.load_pem_private_key(meta_raw, meta_password)
    if v['mode'] == 'production':
        assert password and meta_password and b'ENCRYPTED PRIVATE KEY' in meta_raw
    assert isinstance(apk, rsa.RSAPrivateKey) and apk.key_size >= 3072 and not extras
    assert isinstance(metadata, rsa.RSAPrivateKey) and metadata.key_size >= 3072
    if v['mode']=='production':
        assert not any(word in cert.subject.rfc4514_string().upper() for word in ('TEMPORARY','TEST ONLY','NONPUBLISHABLE')), 'Test certificate cannot be production'
    if v['mode']=='rehearsal':
        assert 'TEMPORARY TEST ONLY NONPUBLISHABLE' in cert.subject.rfc4514_string().upper(), 'Rehearsal requires a labelled test certificate'
    der = cert.public_bytes(serialization.Encoding.DER)
    pub = lambda k: k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert pub(apk) == cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    spki = pub(metadata)
    assert pub(apk) != spki, 'APK and metadata keys must be separate'
    assert sha(der) == v['certificateSha256'] and sha(spki) == v['metadataSpkiSha256'], 'External identity pin mismatch'
    assert sha(der) != '8c0f45c692eabe55cee10e0741131b372b5b7180980644e6c9bf7ce20d9c79a4'
    assert sha(spki) != '3e1eb63894b943bdf47499bf936c2335531f75a29753da8a84d2633a0b42d4f0'
    temp = tempfile.TemporaryDirectory(prefix='drtv-sign-', dir=path.parent)
    atexit.register(temp.cleanup)
    key_path = Path(temp.name) / 'apk.pk8'; cert_path = Path(temp.name) / 'apk.der'
    key_path.write_bytes(apk.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key_path.chmod(0o600); cert_path.write_bytes(der)
    nums = metadata.public_key().public_numbers()
    def integer(n): return base64.urlsafe_b64encode(n.to_bytes((n.bit_length()+7)//8, 'big')).decode().rstrip('=')
    trust = dict(schema=3, developmentOnly=v['mode']=='rehearsal', commonCertificate=sha(der),
                 releaseSpki=base64.b64encode(spki).decode(),
                 releaseKey=dict(kty='RSA', alg='RS256', ext=True, key_ops=['verify'], n=integer(nums.n), e=integer(nums.e)))
    _loaded = dict(path=path, profile=v, key=key_path, cert=cert_path, metadata=metadata, trust=trust)
    return _loaded


def sign(value):
    payload = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    key = load()['metadata']
    signature = key.sign(payload.encode(), padding.PKCS1v15(), hashes.SHA256())
    return dict(payload=payload, signature=base64.b64encode(signature).decode())


def exclude_private(roots):
    """Offline defense in depth against the actual loaded identities, never logging them."""
    state=load();profile=state['profile']
    needles=[Path(profile['apkContainer']).read_bytes(),Path(profile['metadataKey']).read_bytes(),
             state['key'].read_bytes(),state['metadata'].private_bytes(
                 serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())]
    needles += [base64.b64encode(n) for n in list(needles)]
    count=0
    for root in roots:
        root=Path(root);assert root.is_dir()
        for p in root.rglob('*'):
            if not p.is_file():continue
            raw=p.read_bytes();assert not any(n in raw for n in needles),'Private material in public output'
            count+=1
    return dict(status='PASS',files=count,privateMaterialPrinted=False)


def authorize(data_path, authorization, authorization_sha256):
    """An owner-reviewed offline public record; no inferred production approval."""
    v = load(); assert v['profile']['mode'] == 'production'
    raw = Path(authorization).read_bytes()
    assert sha(raw) == authorization_sha256, 'Independent approval record pin required'
    a = json.loads(raw)
    assert set(a) == {'schema', 'approved', 'releaseDataSha256', 'trustSha256', 'website', 'endpoint', 'upgradeFrom'}
    assert a['schema'] == 1 and a['approved'] is True
    assert a['releaseDataSha256'] == sha(Path(data_path).read_bytes())
    trust_bytes = (json.dumps(v['trust'], indent=2, ensure_ascii=False)+'\n').encode()
    assert a['trustSha256'] == sha(trust_bytes)
    from urllib.parse import urlsplit
    for name in ('website', 'endpoint'):
        u = urlsplit(a[name]); assert u.scheme == 'https' and u.hostname and not u.username and not u.password and not u.fragment
        assert not u.hostname.endswith('.invalid') and u.hostname not in ('localhost', '127.0.0.1')
    assert isinstance(a['upgradeFrom'],list) and len(a['upgradeFrom'])<=32
    return a


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Export public trust only; never generates keys or authorizes a release.')
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--export-trust', type=Path, required=True)
    args = parser.parse_args()
    assert not args.export_trust.exists(), 'New public output required'
    v = load(args.profile)
    args.export_trust.write_text(json.dumps(v['trust'], indent=2, ensure_ascii=False)+'\n')
    args.export_trust.chmod(0o644)
    print(json.dumps(dict(publicTrustSha256=sha(args.export_trust.read_bytes()),
                          certificateSha256=v['trust']['commonCertificate'],
                          metadataSpkiSha256=v['profile']['metadataSpkiSha256'])))
