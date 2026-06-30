package ccadb_data

import "crypto/sha256"

func GetCACertCapabilitiesBySHA256(sha256Fingerprint [sha256.Size]byte) *caCertCapabilities {
	return caCertCapabilitiesMap[sha256Fingerprint]
}

func GetIssuerCapabilitiesByKeyIdentifier(b64KeyIdentifier string) *issuerCapabilities {
	return issuerCapabilitiesMap[b64KeyIdentifier]
}

func GetIssuerSPKISHA256ByKeyIdentifier(b64KeyIdentifier string) ([sha256.Size]byte, bool) {
	issuerSPKISHA256, ok := issuerSPKISHA256Map[b64KeyIdentifier]
	return issuerSPKISHA256, ok
}

func GetCACertificateBySHA256(sha256Fingerprint [sha256.Size]byte) ([]byte, bool) {
	der, ok := certificateDERMap[sha256Fingerprint]
	return der, ok
}

func LoadAllCACertificates() {
	readAllCACertificatePEMsCSVOnce.Do(readAllCACertificatePEMsCSV)
}
