# Security policy

Please report security issues privately through [GitHub Security Advisories for eu-eidas-cert-auth](https://github.com/marxgavilan/eu-eidas-cert-auth/security/advisories). Include a reproducible description and affected version. Do not attach real private keys, certificates, identity data or production URLs.

The trust chain begins with signer fingerprints published in the EU Official Journal. Review changes to that publication and the pivot mechanism before updating pins. Invalid signatures, unknown signers, expired lists and empty imports reject without changing the live store. `--force` only bypasses the CA count guard.

`optional_no_ca` relies on the application to authenticate the presented certificate. Make the PHP origin unreachable from the public network, apply validation to every protected route, and never accept a browser certificate header by default. A trusted proxy must strip the incoming header and inject its own value. Keep the live trust store and older generations outside a web root.

The package does not log certificate PEMs or identities. Revocation endpoints are chosen by certificate issuers and may use HTTP. The transport rejects private or reserved DNS answers and pins the selected public address; use deployment egress controls as well. Monitor OCSP/CRL failures and do not enable `softFailRevocation` without a documented policy. Keep dependencies and the OJ pins under review.
