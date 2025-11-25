package ccadb_data

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"os"
	"strings"

	"go.uber.org/zap"
)

// Map of CA Certificate capabilities, indexed by SHA-256(Certificate).
type caCertCapabilities struct {
	CertificateRecordType string
	TlsCapable            bool
	TlsEvCapable          bool
	SmimeCapable          bool
	CodeSigningCapable    bool
}

var caCertCapMap map[[sha256.Size]byte]*caCertCapabilities

// Map of Issuer capabilities, indexed by Base64(Key Identifier).
type issuerCapabilities struct {
	caCertCapabilities
}

var issuerCapMap map[string]*issuerCapabilities

const (
	CCADB_CSV_FILENAME        = "AllCertificateRecordsCSVFormatv4"
	CCADB_RECORD_ROOT         = "Root Certificate"
	CCADB_RECORD_INTERMEDIATE = "Intermediate Certificate"
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

func init() {
	// Configure logger.
	cfg := zap.NewProductionConfig() // "info" and above; JSON output.
	cfg.DisableCaller = true
	logger, err := cfg.Build()
	if err != nil {
		panic("Logger could not be initialized: " + err.Error())
	}
	defer logger.Sync()

	// Read CCADB All Certificate Information CSV file, if available.
	ccadbCsvData, err := os.ReadFile(CCADB_CSV_FILENAME)
	if err != nil {
		logger.Info(
			"CSV file could not be read",
			zap.Error(err),
			zap.String("csv_filename", CCADB_CSV_FILENAME),
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
			zap.String("csv_filename", CCADB_CSV_FILENAME),
		)
		return
	} else if len(records) == 0 {
		logger.Error(
			"CSV file is empty",
			zap.String("csv_filename", CCADB_CSV_FILENAME),
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
				zap.String("csv_filename", CCADB_CSV_FILENAME),
			)
			return
		}
	}

	// Create maps of CA certificate capabilities.
	caCertCapMap = make(map[[sha256.Size]byte]*caCertCapabilities)
	issuerCapMap = make(map[string]*issuerCapabilities)
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
		caCertCapMap[sha256Array] = &ccc

		// Populate/update the map of CA certificate capabilities indexed by key identifier.
		keyIdentifier := line[csvIdx[IDX_SUBJECTKEYIDENTIFIER]]
		if ic := issuerCapMap[keyIdentifier]; ic != nil {
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
			issuerCapMap[line[csvIdx[IDX_SUBJECTKEYIDENTIFIER]]] = &issuerCapabilities{
				caCertCapabilities: ccc,
			}
		}
	}
}

func GetCACertCapabilitiesBySHA256(sha256Fingerprint [sha256.Size]byte) *caCertCapabilities {
	return caCertCapMap[sha256Fingerprint]
}

func GetIssuerCapabilitiesByKeyIdentifier(b64KeyIdentifier string) *issuerCapabilities {
	return issuerCapMap[b64KeyIdentifier]
}
