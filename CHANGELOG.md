# Changelog

All notable changes are recorded here. This project follows semantic versioning and [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.1] - 2026-09-29

### Changed

- Renamed the repository to `eu-eidas-cert-auth` and updated its documentation and links. The Composer package remains `iberfacil/eidas-cert-auth`.
- Made the Laravel doctor command's configuration error handling compatible with PHPStan on PHP 8.2–8.4.

## [0.1.0] - 2026-09-29

### Added

- Named validation profiles for countries, qualification, person type, DNIe, optional OID policies, and revocation; Laravel middleware profile parameters.
- Authentication by default for certificates with client-auth usage chained to an accepted CA/QC TSL anchor, without requiring QcCompliance or a policy OID.
- DNIe opt-out and distinct rejection reasons for usage, qualification, policy, and profile checks.
- Protected AIA intermediate retrieval and a per-validator cache.
- Support for absent client-auth EKU and checksum-validated bare Spanish DNI/NIE serial numbers.
- Framework-free signed EU LOTL and national TSL importer, including OJ signer pins, service status history, a CA retention guard and atomic store generations.
- Certificate chain, purpose, qualified-statement and OCSP/CRL validation with typed results and country identity extractors.
- Optional Laravel provider, middleware, commands, events and published configuration; standalone CLI.
- Offline generated-PKI tests, CI for PHP 8.2–8.4, PHPStan and Pint.
