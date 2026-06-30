# ccadb_data [![Go Report](https://goreportcard.com/badge/github.com/crtsh/ccadb_data)](https://goreportcard.com/report/github.com/crtsh/ccadb_data)

CCADB CSV report archive and Go parsing library.

## CCADB CSV Reports

The following CCADB CSV Reports are included in this repository:

- `AllCertificatePEMsCSVFormat_NotBeforeYear_YYYY`, where YYYY is every year since 1994.

- `AllCertificateRecordsCSVFormatV5`.

## Versioning

The latest versions of the upstream CSV reports are fetched hourly by a GitHub Action. Any changes are automatically committed. If one or more CA certificates is newly disclosed to CCADB, a Release is tagged using a [Scalable Calendar Versioning](https://www.reddit.com/r/golang/comments/1jzucpw/scalable_calendar_versioning_calver_semver/) format (`v1.YYYYMMDD.HHMMSS`).

## Parsing Library

The parsing library provides lookup functions that assist:
- [ctlint](https://github.com/crtsh/ctlint) with verifying CT SCTs.
- [ctsubmit](https://github.com/crtsh/ctsubmit) with automatic certificate chain discovery and issuer identification.
- [pkimetal](https://github.com/pkimetal/pkimetal) with detecting certificate profiles.

### API Functions

#### `GetCACertCapabilitiesBySHA256(sha256Fingerprint [sha256.Size]byte) *caCertCapabilities`

Returns the CCADB-reported capabilities for a CA certificate identified by its SHA-256 fingerprint. The returned struct includes `CertificateRecordType`, `TlsCapable`, `TlsEvCapable`, `SmimeCapable`, `CodeSigningCapable`, and `HasVMCAudit`.

#### `LoadAllCACertificates()`

Loads the DER-encoded bytes for all CA certificates from the embedded PEM CSV data files. Must be called before using `GetCACertificateBySHA256`.

#### `GetCACertificateBySHA256(sha256Fingerprint [sha256.Size]byte) ([]byte, bool)`

Returns the DER-encoded certificate bytes for the CA certificate identified by its SHA-256 fingerprint. Requires `LoadAllCACertificates` to have been called first. Used by ctsubmit for automatic certificate chain discovery.

#### `GetIssuerCapabilitiesByKeyIdentifier(b64KeyIdentifier string) *issuerCapabilities`

Returns the merged capabilities across all CA certificates that share the given Base64-encoded Subject Key Identifier.

#### `GetIssuerSPKISHA256ByKeyIdentifier(b64KeyIdentifier string) ([sha256.Size]byte, bool)`

Returns the SHA-256 hash of the SubjectPublicKeyInfo for the issuer identified by the given Base64-encoded Subject Key Identifier. Used by ctsubmit and ctlint to verify CT SCTs.

For full documentation, see [here](https://pkg.go.dev/github.com/crtsh/ccadb_data).

## Command-line Tools

- The [ski_spki](cmd/ski_spki) tool produces [ski_spkisha256.csv](data/ski_spkisha256.csv), which maps Subject Key Identifiers to the corresponding SHA-256(SubjectPublicKeyInfo) hashes needed for verifying CT SCTs.

- The [url_check](cmd/url_check) tool performs a basic liveness check on URLs found in [AllCertificateRecordsCSVFormatV5](data/AllCertificateRecordsCSVFormatV5).