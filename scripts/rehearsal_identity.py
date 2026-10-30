"""Generate labelled disposable identities only; never a permanent production key."""
if not __debug__:
    raise RuntimeError('Optimized Python is unsupported')
import datetime
from product_common import save, sha


def create(folder):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    folder.mkdir(mode=0o700)
    apk=rsa.generate_private_key(public_exponent=65537,key_size=3072)
    meta=rsa.generate_private_key(public_exponent=65537,key_size=3072)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'DRTV TEMPORARY TEST ONLY NONPUBLISHABLE')])
    now=datetime.datetime.now(datetime.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(apk.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(days=1))
          .not_valid_after(now+datetime.timedelta(days=30)).sign(apk,hashes.SHA256()))
    container=folder/'test-only.p12';key=folder/'metadata-test-only.pem'
    container.write_bytes(pkcs12.serialize_key_and_certificates(b'test-only',apk,cert,None,serialization.NoEncryption()))
    key.write_bytes(meta.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    container.chmod(0o600);key.chmod(0o600)
    spki=meta.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    profile=folder/'profile.json'
    save(profile,dict(schema=1,mode='rehearsal',apkContainer=str(container),metadataKey=str(key),
                      certificateSha256=sha(cert.public_bytes(serialization.Encoding.DER)),metadataSpkiSha256=sha(spki)))
    profile.chmod(0o600)
    return profile
