# eu-eidas-cert-auth agent integration guide

The `iberfacil/eidas-cert-auth` package validates client certificates against signed eIDAS trusted lists. Its repository is [eu-eidas-cert-auth](https://github.com/marxgavilan/eu-eidas-cert-auth). The framework-free core is in `src/`; Laravel support is in `src/Laravel/`.

1. Install the package and publish Laravel configuration only if needed.
2. Set a private, writable `store_path` whose parent exists; the live store path must be absent or a symlink.
3. Review `region`, `countries`, service types, the Official Journal LOTL signer pins and revocation policy with the application owner.
4. Run `eidas:trust-list:update --dry-run`, review additions and removals, then run the update. `--force` only overrides the count guard.
5. Configure TLS termination as shown in the README and protect every certificate-authentication route with `ValidateClientCertificate` or equivalent validation.
6. Read the certificate only from `SSL_CLIENT_CERT` as a server variable. A header is permitted only with a configured exact proxy IP allowlist and a proxy that strips client-supplied copies.
7. Never store or log certificate PEMs, private keys, identity data or revocation payloads unless the application owner explicitly designs a privacy policy for them.

Use `FakeTransport` and generated test PKI for local tests. Do not query official lists during tests. Run PHPUnit, PHPStan and Pint before changing integrations. Do not publish or push this repository without owner approval.
