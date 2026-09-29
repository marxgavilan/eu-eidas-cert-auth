import sys, datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
d, case = sys.argv[1], sys.argv[2]
issuer = x509.load_pem_x509_certificate(open(f"{d}/issuer.pem","rb").read())
kname = "rogue" if case == "rogue" else "issuer"
k = serialization.load_pem_private_key(open(f"{d}/{kname}.key","rb").read(), None)
now = datetime.datetime.now(datetime.timezone.utc)
last, nxt = (now - datetime.timedelta(days=30), now - datetime.timedelta(days=20)) if case == "expired" else (now, now + datetime.timedelta(days=1))
b = x509.CertificateRevocationListBuilder().issuer_name(issuer.subject).last_update(last).next_update(nxt)
sys.stdout.buffer.write(b.sign(k, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
