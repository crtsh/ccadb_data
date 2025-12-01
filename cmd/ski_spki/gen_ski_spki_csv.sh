#!/bin/bash

echo "Subject Key Identifier,SHA-256(Subject Public Key Info)" > ../../data/ski_spkisha256.csv
go run main.go | sort | uniq >> ../../data/ski_spkisha256.csv
