# Changelog

All notable changes are recorded here. This project follows semantic versioning and [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- DNIe authentication policy exception scoped to a signed CA/QC TSL anchor with ForeSignatures, plus protected AIA intermediate retrieval and a per-validator cache.
- Support for absent client-auth EKU and checksum-validated bare Spanish DNI/NIE serial numbers.
- Framework-free signed EU LOTL and national TSL importer, including OJ signer pins, service status history, a CA retention guard and atomic store generations.
- Certificate chain, purpose, qualified-statement and OCSP/CRL validation with typed results and country identity extractors.
- Optional Laravel provider, middleware, commands, events and published configuration; standalone CLI.
- Offline generated-PKI tests, CI for PHP 8.2–8.4, PHPStan and Pint.
