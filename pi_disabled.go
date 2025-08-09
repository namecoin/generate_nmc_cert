//go:build !encaya_pi
// +build !encaya_pi

package main

import (
	"crypto/x509"
)

func applyPiDomainAIAParentCA(template *x509.Certificate, stapled map[string]string) {
}

func applyPiDomainCA(template *x509.Certificate) {
}
