package ccadb_data

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"
	"testing/fstest"
)

func TestParseCertificateRecordsCSV(t *testing.T) {
	headers := []string{
		"Unused",
		"SHA-256 Fingerprint",
		"Subject Key Identifier",
		"Certificate Record Type",
		"TLS Capable",
		"TLS EV Capable",
		"S/MIME Capable",
		"Code Signing Capable",
		"VMC Audit Statement Date",
	}
	makeRecord := func(fingerprint, keyIdentifier, recordType string, tls, tlsEV, smime, codeSigning string, auditDate string) []string {
		return []string{"unused", fingerprint, keyIdentifier, recordType, tls, tlsEV, smime, codeSigning, auditDate}
	}
	firstFingerprint := strings.Repeat("01", sha256.Size)
	secondFingerprint := strings.Repeat("02", sha256.Size)
	rows := [][]string{
		headers,
		makeRecord(firstFingerprint, "shared-key", CCADB_RECORD_INTERMEDIATE, "True", "False", "False", "False", ""),
		makeRecord(secondFingerprint, "shared-key", CCADB_RECORD_ROOT, "False", "True", "True", "True", "2026-01-01"),
		makeRecord("invalid-hex", "invalid-key", CCADB_RECORD_ROOT, "True", "False", "False", "False", ""),
		makeRecord("01", "short-fingerprint", CCADB_RECORD_ROOT, "True", "False", "False", "False", ""),
		{"short record"},
	}
	certificateMap := make(map[[sha256.Size]byte]*caCertCapabilities)
	issuerMap := make(map[string]*issuerCapabilities)
	parseCertificateRecordsCSV(encodeCSV(t, rows), certificateMap, issuerMap)

	var firstHash, secondHash [sha256.Size]byte
	copy(firstHash[:], bytes.Repeat([]byte{1}, sha256.Size))
	copy(secondHash[:], bytes.Repeat([]byte{2}, sha256.Size))
	if got := certificateMap[firstHash]; got == nil || *got != (caCertCapabilities{
		CertificateRecordType: CCADB_RECORD_INTERMEDIATE,
		TlsCapable:            true,
	}) {
		t.Errorf("capabilities for first certificate = %+v", got)
	}
	if got := certificateMap[secondHash]; got == nil || *got != (caCertCapabilities{
		CertificateRecordType: CCADB_RECORD_ROOT,
		TlsEvCapable:          true,
		SmimeCapable:          true,
		CodeSigningCapable:    true,
		HasVMCAudit:           true,
	}) {
		t.Errorf("capabilities for second certificate = %+v", got)
	}
	wantIssuer := caCertCapabilities{
		CertificateRecordType: CCADB_RECORD_ROOT,
		TlsCapable:            true,
		TlsEvCapable:          true,
		SmimeCapable:          true,
		CodeSigningCapable:    true,
		HasVMCAudit:           true,
	}
	if got := issuerMap["shared-key"]; got == nil || got.caCertCapabilities != wantIssuer {
		t.Errorf("merged issuer capabilities = %+v, want %+v", got, wantIssuer)
	}
	if len(certificateMap) != 2 || len(issuerMap) != 1 {
		t.Errorf("invalid records were not skipped: certificates=%d issuers=%d", len(certificateMap), len(issuerMap))
	}
}

func TestParseCertificateRecordsCSVWithMissingOrEmptyInput(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "empty", data: nil},
		{name: "missing headers", data: []byte("header\nvalue\n")},
		{name: "malformed CSV", data: []byte("\"unterminated")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			certificateMap := make(map[[sha256.Size]byte]*caCertCapabilities)
			issuerMap := make(map[string]*issuerCapabilities)
			parseCertificateRecordsCSV(test.data, certificateMap, issuerMap)
			if len(certificateMap) != 0 || len(issuerMap) != 0 {
				t.Fatalf("unexpected records from invalid input: certificates=%d issuers=%d", len(certificateMap), len(issuerMap))
			}
		})
	}
}

func TestParseSKIAndSHA256HashCSV(t *testing.T) {
	wantHash := bytes.Repeat([]byte{0xab}, sha256.Size)
	data := encodeCSV(t, [][]string{
		{"Subject Key Identifier", "SHA-256(SPKI)"},
		{"valid-key", base64.StdEncoding.EncodeToString(wantHash)},
		{"invalid-base64", "not base64!"},
		{"short-hash", base64.StdEncoding.EncodeToString([]byte{1, 2, 3})},
	})

	gotMap := make(map[string][sha256.Size]byte)
	parseSKIAndSHA256HashCSV(data, gotMap)
	var expected [sha256.Size]byte
	copy(expected[:], wantHash)
	if len(gotMap) != 1 || gotMap["valid-key"] != expected {
		t.Fatalf("parsed SKI hashes = %v, want only valid-key mapped to %x", gotMap, expected)
	}
}

func TestParseSKIAndSHA256HashCSVWithMalformedOrEmptyInput(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "empty", data: nil},
		{name: "wrong field count", data: []byte("header,hash\nkey,hash,extra\n")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotMap := make(map[string][sha256.Size]byte)
			parseSKIAndSHA256HashCSV(test.data, gotMap)
			if len(gotMap) != 0 {
				t.Fatalf("unexpected SKI hashes from invalid input: %v", gotMap)
			}
		})
	}
}

func TestReadSKIAndSHA256HashCSVWithMissingFile(t *testing.T) {
	gotMap := make(map[string][sha256.Size]byte)
	readSKIAndSHA256HashCSV(gotMap, "data/missing.csv")
	if len(gotMap) != 0 {
		t.Fatalf("missing file unexpectedly populated SKI hashes: %v", gotMap)
	}
}

func TestLoadCACertificatesFromFilesystem(t *testing.T) {
	fingerprint := strings.Repeat("01", sha256.Size)
	wantDER := []byte{1, 2, 3, 4}
	otherDER := []byte{5, 6, 7, 8}
	validPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: wantDER}))
	duplicatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherDER}))
	validCSV := encodeCSV(t, [][]string{
		{"SHA-256 Fingerprint", "Certificate PEM"},
		{fingerprint, validPEM},
		{fingerprint, duplicatePEM},
		{"not-hex", validPEM},
		{"01", validPEM},
		{strings.Repeat("02", sha256.Size), "not a PEM block"},
	})
	malformedCSV := encodeCSV(t, [][]string{
		{"SHA-256 Fingerprint", "Certificate PEM"},
		{"01", "one", "too many fields"},
	})
	filesystem := fstest.MapFS{
		"cmd/ski_spki/data/valid.csv":          {Data: validCSV},
		"cmd/ski_spki/data/malformed.csv":      {Data: malformedCSV},
		"cmd/ski_spki/data/nested/ignored.csv": {Data: validCSV},
	}

	gotMap := loadCACertificates(filesystem)
	var fingerprintHash [sha256.Size]byte
	fingerprintBytes, err := hex.DecodeString(fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	copy(fingerprintHash[:], fingerprintBytes)
	if len(gotMap) != 1 || !bytes.Equal(gotMap[fingerprintHash], wantDER) {
		t.Fatalf("loaded certificates = %v, want first DER for fingerprint %x", gotMap, fingerprintHash)
	}
	if got := loadCACertificates(fstest.MapFS{}); len(got) != 0 {
		t.Fatalf("loading from a filesystem without the data directory returned %d certificates", len(got))
	}
}

func encodeCSV(t *testing.T, records [][]string) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := csv.NewWriter(&output)
	for _, record := range records {
		if err := writer.Write(record); err != nil {
			t.Fatalf("write CSV fixture: %v", err)
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		t.Fatalf("flush CSV fixture: %v", err)
	}
	return output.Bytes()
}
