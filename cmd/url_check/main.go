package main

import (
	"crypto/tls"
	_ "embed"
	"encoding/csv"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hueristiq/hq-go-url/extractor"
)

var httpClient *http.Client

func main() {
	httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: time.Duration(30) * time.Second,
	}

	// Validate the command-line arguments.
	switch len(os.Args) {
	case 2, 3:
	default:
		fmt.Fprintf(os.Stderr, "Usage: %s <AllCertificateRecordsCSVFormatv4> [CA Owner]\n", os.Args[0])
		os.Exit(1)
	}

	// Read the CSV file.
	csvReport, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading CSV file: %v\n", err)
		os.Exit(1)
	}

	// Parse the CSV file.
	reader := csv.NewReader(strings.NewReader(string(csvReport)))
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true
	reader.ReuseRecord = true
	records, err := reader.ReadAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing CSV file: %v\n", err)
		os.Exit(1)
	} else if len(records) == 0 {
		fmt.Fprintf(os.Stderr, "CSV file is empty\n")
		os.Exit(1)
	}

	// Determine the indexes of the required fields.
	caOwnerIdx := -1
	subCAOwnerIdx := -1
	revocationStatusIdx := -1
	validToIdx := -1
	for i, v := range records[0] {
		switch v {
		case "CA Owner":
			caOwnerIdx = i
		case "Subordinate CA Owner":
			subCAOwnerIdx = i
		case "Revocation Status":
			revocationStatusIdx = i
		case "Valid To (GMT)":
			validToIdx = i
		}
	}
	if caOwnerIdx == -1 || subCAOwnerIdx == -1 || revocationStatusIdx == -1 || validToIdx == -1 {
		fmt.Fprintf(os.Stderr, "An expected field was not found in the CSV header\n")
		os.Exit(1)
	}

	// Parse the CSV data.
	results := make(map[string][]string)
	e := extractor.New(extractor.WithScheme())
	regex := e.CompileRegex()
	for _, record := range records[1:] {
		// Skip revoked certificates.
		switch record[revocationStatusIdx] {
		case "Revoked", "Parent Cert Revoked":
			continue
		}
		// Skip expired certificates.
		notAfter, err := time.Parse(time.DateOnly, record[validToIdx])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing Valid To date: %v\n", err)
			os.Exit(1)
		} else if time.Now().After(notAfter) {
			continue
		}
		// If required, filter by CA Owner.
		if len(os.Args) < 3 || record[caOwnerIdx] == os.Args[2] || record[subCAOwnerIdx] == os.Args[2] {
			// Add all encountered URLs to a map.
			for _, field := range record {
				for _, url := range regex.FindAllString(field, -1) {
					results[url] = []string{record[caOwnerIdx], record[subCAOwnerIdx]}
				}
			}
		}
	}

	// Wait for all URL checks to complete.
	var wg sync.WaitGroup
	for url, result := range results {
		wg.Go(func() { checkURL(append(result, url)) })
	}
	wg.Wait()
}

func checkURL(result []string) {
	req, err := http.NewRequest("HEAD", result[2], nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(1)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		result = append(result, err.Error())
	} else if resp.StatusCode != 200 {
		result = append(result, fmt.Sprintf("HTTP %d", resp.StatusCode))
	} else {
		return
	}

	csvWriter := csv.NewWriter(os.Stdout)
	csvWriter.Write(result)
	if err = csvWriter.Error(); err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(1)
	}
	csvWriter.Flush()
	if err = csvWriter.Error(); err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(1)
	}
}
