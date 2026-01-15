# ccadb_data [![Go Report](https://goreportcard.com/badge/github.com/crtsh/ccadb_data)](https://goreportcard.com/report/github.com/crtsh/ccadb_data)

CCADB CSV report archive and Go parsing library.

## CCADB CSV Reports

The following CCADB CSV Reports are included in this repository:

- `AllCertificatePEMsCSVFormat_NotBeforeYear_YYYY`, where YYYY is every year since 1994.

- `AllCertificateRecordsCSVFormatv4`.

## Versioning

The latest versions of the upstream CSV reports are fetched hourly by a GitHub Action. Any changes are automatically committed. If one or more CA certificates is newly disclosed to CCADB, a Release is tagged using a [Scalable Calendar Versioning](https://www.reddit.com/r/golang/comments/1jzucpw/scalable_calendar_versioning_calver_semver/) format (`v1.YYYYMMDD.HHMMSS`).

## Parsing Library

The parsing library currently provides functions that assist [ctlint](https://github.com/crtsh/ctlint) with verifying CT SCTs and [pkimetal](https://github.com/pkimetal/pkimetal) with detecting certificate profiles.

For documentation, see [here](https://pkg.go.dev/github.com/crtsh/ccadb_data).