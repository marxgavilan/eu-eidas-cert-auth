"""Generate offline OCSP cases from the disposable test PKI."""
import datetime
import pathlib
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp

root = pathlib.Path(sys.argv[1])
case = sys.argv[2]

def cert(name):
    return x509.load_pem_x509_certificate((root / f"{name}.pem").read_bytes())

def key(name):
    return serialization.load_pem_private_key((root / f"{name}.key").read_bytes(), None)

issuer = cert("issuer")
target = cert("cert")
signer_cert = issuer
signer_key = key("issuer")
now = datetime.datetime.now(datetime.timezone.utc)
this_update = now
next_update = now + datetime.timedelta(days=1)
if case == "old_no_next":
    this_update = now - datetime.timedelta(days=700)
    next_update = None
elif case == "expired":
    this_update = now - datetime.timedelta(days=10)
    next_update = now - datetime.timedelta(days=3)
elif case == "other_cert":
    target = cert("other")
elif case == "other_signer":
    signer_cert = cert("rogue")
    signer_key = key("rogue")
elif case == "delegated_no_eku":
    signer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signer_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Delegated without EKU")]))
        .issuer_name(issuer.subject)
        .public_key(signer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key("issuer"), hashes.SHA256())
    )

builder = (
    ocsp.OCSPResponseBuilder()
    .add_response(
        cert=target,
        issuer=issuer,
        algorithm=hashes.SHA1(),
        cert_status=ocsp.OCSPCertStatus.GOOD,
        this_update=this_update,
        next_update=next_update,
        revocation_time=None,
        revocation_reason=None,
    )
    .responder_id(ocsp.OCSPResponderEncoding.HASH, signer_cert)
)
if signer_cert != issuer:
    builder = builder.certificates([signer_cert])
sys.stdout.buffer.write(builder.sign(signer_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
