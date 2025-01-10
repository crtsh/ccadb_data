#!/bin/bash

go run main.go | sort | uniq > ../../data/ski_spki.csv
