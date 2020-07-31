# CIRCL cve-search API Go Wrapper

[![Go Report Card](https://goreportcard.com/badge/github.com/jon77p/go-circlcve)](https://goreportcard.com/report/github.com/jon77p/go-circlcve)
[![Documentation](https://godoc.org/github.com/jon77p/go-circlcve?status.svg)](https://godoc.org/github.com/jon77p/go-circlcve)

## Supported Functionality

- [ ] Convert a CPE (Common Platform Enumeration) code in CPE2.2 or CPE2.3 format to the CPE2.3 standard, stripped of appendices

- [ ] Retrieve all vendors

- [ ] Retrieve all products associated to a vendor

- [ ] Retrieve all CVE (Common Vulnerabilities and Exposures) entries per vendor and a specific product

- [ ] Retrieve all CVE entries related to a product in CPE2.2 or CPE2.3 format

- [x] Get CVE information per CVE-ID

- [x] Output a list of all CWEs (Common Weakness Enumerations)

- [x] Output a list of CAPEC (Common Attack Pattern Enumeration and Classifaction) attack types related to a CWE

- [ ] Get the last n (default=30) CVEs, including CAPEC, CWE, and CPE expansions

- [ ] Retrieve a list of CVEs matching a specific query

- [ ] Retrieve CIRCL database information and last refresh time

- [ ] Convert a given vendor, product, and version into a CPE2.3 compliant format
