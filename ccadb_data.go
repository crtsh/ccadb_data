package ccadb_data

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"strings"

	"go.uber.org/zap"
)

//go:embed data/AllCertificateRecordsCSVFormatv4
var f embed.FS

// Map of CA Certificate capabilities, indexed by SHA-256(Certificate).
type caCertCapabilities struct {
	CertificateRecordType string
	TlsCapable            bool
	TlsEvCapable          bool
	SmimeCapable          bool
	CodeSigningCapable    bool
}

var caCertCapabilitiesMap map[[sha256.Size]byte]*caCertCapabilities

// Map of Issuer capabilities, indexed by Base64(Key Identifier).
type issuerCapabilities struct {
	caCertCapabilities
}

var issuerCapabilitiesMap map[string]*issuerCapabilities

// Map of Issuer SPKI SHA-256 hashes, indexed by Base64(Key Identifier).
var issuerSPKISHA256Map map[string][32]byte

const (
	CCADB_CSV_PATH            = "data/AllCertificateRecordsCSVFormatv4"
	CCADB_RECORD_ROOT         = "Root Certificate"
	CCADB_RECORD_INTERMEDIATE = "Intermediate Certificate"
	SKI_SPKISHA256_PATH       = "data/ski_spkisha256.csv"
)

const (
	IDX_SHA256FINGERPRINT int = iota
	IDX_SUBJECTKEYIDENTIFIER
	IDX_CERTIFICATERECORDTYPE
	IDX_TLSCAPABLE
	IDX_TLSEVCAPABLE
	IDX_SMIMECAPABLE
	IDX_CODESIGNINGCAPABLE
	MAX_IDX
)

var logger *zap.Logger

func init() {
	// Configure logger.
	var err error
	cfg := zap.NewProductionConfig() // "info" and above; JSON output.
	cfg.DisableCaller = true
	logger, err = cfg.Build()
	if err != nil {
		panic("Logger could not be initialized: " + err.Error())
	}
	defer logger.Sync()

	// Initialize maps.
	caCertCapabilitiesMap = make(map[[sha256.Size]byte]*caCertCapabilities)
	issuerCapabilitiesMap = make(map[string]*issuerCapabilities)
	issuerSPKISHA256Map = make(map[string][32]byte)

	// Read CSV data.
	readAllCertificateRecordsCSV()
	readIssuerSPKIHashCSV()
}

func readAllCertificateRecordsCSV() {
	// Read CCADB All Certificate Information CSV file.
	ccadbCsvData, err := f.ReadFile(CCADB_CSV_PATH)
	if err != nil {
		logger.Info(
			"CSV file could not be read",
			zap.Error(err),
			zap.String("file_path", CCADB_CSV_PATH),
		)
		return
	}

	// Parse CSV data.
	reader := csv.NewReader(strings.NewReader(string(ccadbCsvData)))
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true
	reader.ReuseRecord = true
	records, err := reader.ReadAll()
	if err != nil {
		logger.Error(
			"CSV file could not be parsed",
			zap.Error(err),
			zap.String("file_path", CCADB_CSV_PATH),
		)
		return
	} else if len(records) == 0 {
		logger.Error(
			"CSV file is empty",
			zap.String("file_path", CCADB_CSV_PATH),
		)
		return
	}

	// Examine the CSV header to find the fields that we need.
	var csvIdx [MAX_IDX]int
	var greatestIdx int
	for i, v := range records[0] {
		switch v {
		case "SHA-256 Fingerprint":
			csvIdx[IDX_SHA256FINGERPRINT] = i
		case "Subject Key Identifier":
			csvIdx[IDX_SUBJECTKEYIDENTIFIER] = i
		case "Certificate Record Type":
			csvIdx[IDX_CERTIFICATERECORDTYPE] = i
		case "TLS Capable":
			csvIdx[IDX_TLSCAPABLE] = i
		case "TLS EV Capable":
			csvIdx[IDX_TLSEVCAPABLE] = i
		case "S/MIME Capable":
			csvIdx[IDX_SMIMECAPABLE] = i
		case "Code Signing Capable":
			csvIdx[IDX_CODESIGNINGCAPABLE] = i
		default:
			continue
		}
		if i > greatestIdx {
			greatestIdx = i
		}
	}
	for _, v := range csvIdx {
		if v == 0 {
			logger.Error(
				"CSV data is missing one or more expected headers",
				zap.String("file_path", CCADB_CSV_PATH),
			)
			return
		}
	}

	// Process CSV data.
	for _, line := range records[1:] {
		if len(line) <= greatestIdx {
			logger.Warn(
				"CSV data has a line that is missing one or more expected fields",
				zap.String("line", strings.Join(line, ",")),
			)
		}

		// Populate the map of CA certificate capabilities indexed by SHA-256 fingerprint.
		ccc := caCertCapabilities{
			CertificateRecordType: line[csvIdx[IDX_CERTIFICATERECORDTYPE]],
			TlsCapable:            line[csvIdx[IDX_TLSCAPABLE]] == "True",
			TlsEvCapable:          line[csvIdx[IDX_TLSEVCAPABLE]] == "True",
			SmimeCapable:          line[csvIdx[IDX_SMIMECAPABLE]] == "True",
			CodeSigningCapable:    line[csvIdx[IDX_CODESIGNINGCAPABLE]] == "True",
		}
		sha256Slice, err := hex.DecodeString(line[csvIdx[IDX_SHA256FINGERPRINT]])
		if err != nil {
			logger.Warn(
				"CSV data contains an invalid hex string",
				zap.String("value", line[csvIdx[IDX_SHA256FINGERPRINT]]),
			)
			continue
		}
		var sha256Array [sha256.Size]byte
		copy(sha256Array[:], sha256Slice)
		caCertCapabilitiesMap[sha256Array] = &ccc

		// Populate/update the map of CA certificate capabilities indexed by key identifier.
		keyIdentifier := line[csvIdx[IDX_SUBJECTKEYIDENTIFIER]]
		if ic := issuerCapabilitiesMap[keyIdentifier]; ic != nil {
			// Multiple CA certificates share this key identifier, so merge the capabilities.
			if ccc.CertificateRecordType == CCADB_RECORD_ROOT {
				ic.CertificateRecordType = CCADB_RECORD_ROOT
			}
			if ccc.TlsCapable {
				ic.TlsCapable = true
			}
			if ccc.TlsEvCapable {
				ic.TlsEvCapable = true
			}
			if ccc.SmimeCapable {
				ic.SmimeCapable = true
			}
			if ccc.CodeSigningCapable {
				ic.CodeSigningCapable = true
			}
		} else {
			issuerCapabilitiesMap[line[csvIdx[IDX_SUBJECTKEYIDENTIFIER]]] = &issuerCapabilities{
				caCertCapabilities: ccc,
			}
		}
	}
}

func readIssuerSPKIHashCSV() {
	// Read SKI -> SHA-256(SPKI) CSV file.
	skiSpkiCsvData, err := f.ReadFile(SKI_SPKISHA256_PATH)
	if err != nil {
		logger.Info(
			"CSV file could not be read",
			zap.Error(err),
			zap.String("file_path", SKI_SPKISHA256_PATH),
		)
		return
	}

	// Parse CSV data.
	reader := csv.NewReader(strings.NewReader(string(skiSpkiCsvData)))
	reader.FieldsPerRecord = 2
	reader.ReuseRecord = true
	records, err := reader.ReadAll()
	if err != nil {
		logger.Error(
			"CSV file could not be parsed",
			zap.Error(err),
			zap.String("file_path", SKI_SPKISHA256_PATH),
		)
		return
	} else if len(records) == 0 {
		logger.Error(
			"CSV file is empty",
			zap.String("file_path", SKI_SPKISHA256_PATH),
		)
		return
	}

	// Process CSV data.
	for _, line := range records[1:] {
		// Decode Base64-encoded SHA-256(SPKI).
		decoded, err := base64.StdEncoding.DecodeString(line[1])
		if err != nil {
			logger.Warn(
				"CSV data contains an invalid Base64 string",
				zap.String("value", line[1]),
			)
			continue
		} else if len(decoded) != sha256.Size {
			logger.Warn(
				"CSV data contains a Base64 string with an invalid length",
				zap.String("value", line[1]),
			)
			continue
		}

		var spkiSHA256 [sha256.Size]byte
		copy(spkiSHA256[:], decoded)
		issuerSPKISHA256Map[line[0]] = spkiSHA256
	}
}

func GetCACertCapabilitiesBySHA256(sha256Fingerprint [sha256.Size]byte) *caCertCapabilities {
	return caCertCapabilitiesMap[sha256Fingerprint]
}

func GetIssuerCapabilitiesByKeyIdentifier(b64KeyIdentifier string) *issuerCapabilities {
	return issuerCapabilitiesMap[b64KeyIdentifier]
}

func GetIssuerSPKISHA256ByKeyIdentifier(b64KeyIdentifier string) ([32]byte, bool) {
	issuerSPKI, ok := issuerSPKISHA256Map[b64KeyIdentifier]
	return issuerSPKI, ok
}
