# Contributing

Work from `main` on a short branch and make focused commits. Explain behavior and risk in the pull request. Update both READMEs and `CHANGELOG.md` when public behavior changes.

Use PHP 8.2+, strict types, Pint, PHPStan level 8 and PHPUnit 11. Run `composer check` before review. Tests must not contact the network: use `FakeTransport` and generate all PKI material and signed XML during the test. Never commit real certificates, keys, customer data, secrets, private platform addresses or captured production responses.

Security fixes should be reported privately as described in [SECURITY.md](SECURITY.md).
