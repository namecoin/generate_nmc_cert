//go:build encaya_pi
// +build encaya_pi

package main

import (
	"crypto/x509"
	"strconv"
	"strings"

	"github.com/ferhatelmas/pi"
)

func applyPiDomainAIAParentCA(template *x509.Certificate, stapled map[string]string) {
	domain := template.PermittedDNSDomains[0]

	// Pi meta-domains are of the form INTEGER.pi.x--nmc.bit
	metaSuffix := ".pi.x--nmc.bit"
	if !strings.HasSuffix(domain, metaSuffix) {
		return
	}

	digitCountStr := strings.TrimSuffix(domain, metaSuffix)

	digitCount, err := strconv.ParseInt(digitCountStr, 10, 0)
	if err != nil {
		return
	}

	actualDigits := pi.Digits(digitCount)

	stapled["pidigits"] = actualDigits
}

func applyPiDomainCA(template *x509.Certificate) {
	domain := template.PermittedDNSDomains[0]

	// Pi meta-domains are of the form INTEGER.pi.x--nmc.bit
	metaSuffix := ".pi.x--nmc.bit"
	if !strings.HasSuffix(domain, metaSuffix) {
		return
	}

	digitCountStr := strings.TrimSuffix(domain, metaSuffix)

	digitCount, err := strconv.ParseInt(digitCountStr, 10, 0)
	if err != nil {
		return
	}

	actualDigits := pi.Digits(digitCount)

	template.IssuingCertificateURL[0] = template.IssuingCertificateURL[0] + "&pidigits=" + actualDigits
}
