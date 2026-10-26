package ccadb_data

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/csv"
	"encoding/hex"
	"strings"
	"testing"
)

func TestCapabilityLookups(t *testing.T) {
	if len(caCertCapabilitiesMap) == 0 {
		t.Fatal("CA certificate capabilities were not loaded")
	}
	for fingerprint, want := range caCertCapabilitiesMap {
		if got := GetCACertCapabilitiesBySHA256(fingerprint); got != want {
			t.Fatalf("GetCACertCapabilitiesBySHA256(%x) = %v, want %v", fingerprint, got, want)
		}
		break
	}

	if len(issuerCapabilitiesMap) == 0 {
		t.Fatal("issuer capabilities were not loaded")
	}
	for keyIdentifier, want := range issuerCapabilitiesMap {
		if got := GetIssuerCapabilitiesByKeyIdentifier(keyIdentifier); got != want {
			t.Fatalf("GetIssuerCapabilitiesByKeyIdentifier(%q) = %v, want %v", keyIdentifier, got, want)
		}
		break
	}

	if len(issuerSPKISHA256Map) == 0 {
		t.Fatal("issuer SPKI hashes were not loaded")
	}
	for keyIdentifier, want := range issuerSPKISHA256Map {
		if got, ok := GetIssuerSPKISHA256ByKeyIdentifier(keyIdentifier); !ok || got != want {
			t.Fatalf("GetIssuerSPKISHA256ByKeyIdentifier(%q) = (%x, %t), want (%x, true)", keyIdentifier, got, ok, want)
		}
		break
	}

	unknownFingerprint := sha256.Sum256([]byte("unknown certificate"))
	if got := GetCACertCapabilitiesBySHA256(unknownFingerprint); got != nil {
		t.Fatalf("GetCACertCapabilitiesBySHA256(unknown fingerprint) = %v, want nil", got)
	}
	if got := GetIssuerCapabilitiesByKeyIdentifier("unknown key identifier"); got != nil {
		t.Fatalf("GetIssuerCapabilitiesByKeyIdentifier(unknown key identifier) = %v, want nil", got)
	}
	if _, ok := GetIssuerSPKISHA256ByKeyIdentifier("unknown key identifier"); ok {
		t.Fatal("GetIssuerSPKISHA256ByKeyIdentifier(unknown key identifier) unexpectedly found a hash")
	}
}

func TestLoadAllCACertificates(t *testing.T) {
	LoadAllCACertificates()
	if len(certificateDERMap) == 0 {
		t.Fatal("no CA certificates were loaded")
	}
	for fingerprint, der := range certificateDERMap {
		if got := sha256.Sum256(der); got != fingerprint {
			t.Errorf("loaded certificate fingerprint = %x, want %x", got, fingerprint)
		}
	}

	var fingerprint [sha256.Size]byte
	var wantDER []byte
	for fingerprint, wantDER = range certificateDERMap {
		break
	}

	gotDER, ok := GetCACertificateBySHA256(fingerprint)
	if !ok {
		t.Fatalf("GetCACertificateBySHA256(%x) did not find a loaded certificate", fingerprint)
	}
	if !bytes.Equal(gotDER, wantDER) {
		t.Fatalf("GetCACertificateBySHA256(%x) returned different DER bytes", fingerprint)
	}
	if got := sha256.Sum256(gotDER); got != fingerprint {
		t.Fatalf("loaded certificate fingerprint = %x, want %x", got, fingerprint)
	}
	if _, err := x509.ParseCertificate(gotDER); err != nil {
		t.Fatalf("loaded DER is not a valid certificate: %v", err)
	}

	loadedCount := len(certificateDERMap)
	LoadAllCACertificates()
	if got := len(certificateDERMap); got != loadedCount {
		t.Fatalf("repeated LoadAllCACertificates changed loaded certificate count from %d to %d", loadedCount, got)
	}
	unknownFingerprint := sha256.Sum256([]byte("unknown certificate"))
	if _, ok := GetCACertificateBySHA256(unknownFingerprint); ok {
		t.Fatal("GetCACertificateBySHA256 unexpectedly found an unknown fingerprint")
	}
}

func TestIssuerCapabilitiesMergeAllMatchingCertificates(t *testing.T) {
	csvData, err := f.ReadFile(CCADB_CSV_PATH)
	if err != nil {
		t.Fatalf("read embedded CCADB records: %v", err)
	}
	reader := csv.NewReader(strings.NewReader(string(csvData)))
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("parse embedded CCADB records: %v", err)
	}
	if len(records) < 2 {
		t.Fatal("embedded CCADB records contain no data rows")
	}

	headerIndexes := make(map[string]int, len(records[0]))
	for index, header := range records[0] {
		headerIndexes[header] = index
	}
	keyIdentifierIndex, ok := headerIndexes["Subject Key Identifier"]
	if !ok {
		t.Fatal("CCADB records are missing the Subject Key Identifier column")
	}
	fingerprintIndex, ok := headerIndexes["SHA-256 Fingerprint"]
	if !ok {
		t.Fatal("CCADB records are missing the SHA-256 Fingerprint column")
	}
	capabilityIndexes := make(map[string]int)
	for _, header := range []string{
		"Certificate Record Type",
		"TLS Capable",
		"TLS EV Capable",
		"S/MIME Capable",
		"Code Signing Capable",
		"VMC Audit Statement Date",
	} {
		index, ok := headerIndexes[header]
		if !ok {
			t.Fatalf("CCADB records are missing the %q column", header)
		}
		capabilityIndexes[header] = index
	}

	expectedByKeyIdentifier := make(map[string]caCertCapabilities)
	duplicateCount := 0
	for rowIndex, record := range records[1:] {
		greatestIndex := fingerprintIndex
		for _, index := range capabilityIndexes {
			if index > greatestIndex {
				greatestIndex = index
			}
		}
		if len(record) <= greatestIndex || len(record) <= keyIdentifierIndex {
			t.Fatalf("CCADB record %d is missing a required field", rowIndex+2)
		}
		keyIdentifier := record[keyIdentifierIndex]
		certificateCapabilities := caCertCapabilities{
			CertificateRecordType: record[capabilityIndexes["Certificate Record Type"]],
			TlsCapable:            record[capabilityIndexes["TLS Capable"]] == "True",
			TlsEvCapable:          record[capabilityIndexes["TLS EV Capable"]] == "True",
			SmimeCapable:          record[capabilityIndexes["S/MIME Capable"]] == "True",
			CodeSigningCapable:    record[capabilityIndexes["Code Signing Capable"]] == "True",
			HasVMCAudit:           record[capabilityIndexes["VMC Audit Statement Date"]] != "",
		}
		fingerprintBytes, err := hex.DecodeString(record[fingerprintIndex])
		if err != nil || len(fingerprintBytes) != sha256.Size {
			continue
		}
		current, exists := expectedByKeyIdentifier[keyIdentifier]
		if !exists {
			expectedByKeyIdentifier[keyIdentifier] = certificateCapabilities
			continue
		}
		duplicateCount++
		if certificateCapabilities.CertificateRecordType == CCADB_RECORD_ROOT {
			current.CertificateRecordType = CCADB_RECORD_ROOT
		}
		current.TlsCapable = current.TlsCapable || certificateCapabilities.TlsCapable
		current.TlsEvCapable = current.TlsEvCapable || certificateCapabilities.TlsEvCapable
		current.SmimeCapable = current.SmimeCapable || certificateCapabilities.SmimeCapable
		current.CodeSigningCapable = current.CodeSigningCapable || certificateCapabilities.CodeSigningCapable
		current.HasVMCAudit = current.HasVMCAudit || certificateCapabilities.HasVMCAudit
		expectedByKeyIdentifier[keyIdentifier] = current
	}
	if duplicateCount == 0 {
		t.Fatal("embedded CCADB records contain no duplicate subject key identifiers")
	}
	if len(expectedByKeyIdentifier) != len(issuerCapabilitiesMap) {
		t.Fatalf("found %d issuer capability entries, want %d", len(issuerCapabilitiesMap), len(expectedByKeyIdentifier))
	}

	for keyIdentifier, want := range expectedByKeyIdentifier {
		got := GetIssuerCapabilitiesByKeyIdentifier(keyIdentifier)
		if got == nil {
			t.Errorf("GetIssuerCapabilitiesByKeyIdentifier(%q) = nil", keyIdentifier)
			continue
		}
		if got.caCertCapabilities != want {
			t.Errorf("issuer capabilities for %q = %+v, want %+v", keyIdentifier, got.caCertCapabilities, want)
		}
	}
}
