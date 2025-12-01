package main

import (
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/csv"
	"encoding/pem"
	"fmt"
	"strings"
)

//go:embed data/*
var files embed.FS

func main() {
	if dirEntry, err := files.ReadDir("data"); err != nil {
		panic(err)
	} else {
		for _, entry := range dirEntry {
			var data []byte
			if data, err = files.ReadFile("data/" + entry.Name()); err != nil {
				panic(err)
			}

			reader := csv.NewReader(strings.NewReader(string(data)))
			reader.FieldsPerRecord = 2
			reader.LazyQuotes = true
			reader.TrimLeadingSpace = true
			reader.ReuseRecord = true
			records, err := reader.ReadAll()
			if err != nil {
				panic(err)
			}

			for _, record := range records[1:] {
				var cert *x509.Certificate
				if block, _ := pem.Decode([]byte(record[1])); block == nil {
					panic(fmt.Errorf("Failed to decode PEM block from Certificate"))
				} else if cert, err = x509.ParseCertificate(block.Bytes); err == nil && cert.SubjectKeyId != nil {
					spkiSHA256 := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
					fmt.Printf("%s,%s\n", base64.StdEncoding.EncodeToString(cert.SubjectKeyId), base64.StdEncoding.EncodeToString(spkiSHA256[:]))
				}
			}
		}
	}
}
