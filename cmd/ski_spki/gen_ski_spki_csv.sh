#!/bin/bash

go run main.go | sort | uniq > ../../data/ski_spkisha256.csv
