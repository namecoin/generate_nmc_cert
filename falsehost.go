// nolint: gofmt, goimports

// Copyright 2009 The Go Authors. All rights reserved.
// Dehydrated certificate modifications Copyright 2015-2021 Jeremy Rand. All
// rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.


// Generate a self-signed X.509 certificate for a TLS server. Outputs to
// 'cert.pem' and 'key.pem' and will overwrite existing files.

// This code has been modified from the stock Go code to generate
// "dehydrated certificates", suitable for inclusion in a Namecoin name.

// Last rebased against Go 1.17.
// Future rebases need to rebase all of the main, parent, aiaparent, and
// falseHost flows.

package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	//"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	//"flag"
	"log"
	"math/big"
	//"net"
	"os"
	//"strings"
	"time"
)

//var (
//	host       = flag.String("host", "", "Comma-separated hostnames and IPs to generate a certificate for")
//	validFrom  = flag.String("start-date", "", "Creation date formatted as Jan 1 15:04:05 2011")
//	validFor   = flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
//	isCA       = flag.Bool("ca", false, "whether this cert should be its own Certificate Authority")
//	rsaBits    = flag.Int("rsa-bits", 2048, "Size of RSA key to generate. Ignored if --ecdsa-curve is set")
//	ecdsaCurve = flag.String("ecdsa-curve", "", "ECDSA curve to use to generate a key. Valid values are P224, P256 (recommended), P384, P521")
//	ed25519Key = flag.Bool("ed25519", false, "Generate an Ed25519 key")
//)

//func publicKey(priv interface{}) interface{} {
//	switch k := priv.(type) {
//	case *rsa.PrivateKey:
//		return &k.PublicKey
//	case *ecdsa.PrivateKey:
//		return &k.PublicKey
//	case ed25519.PrivateKey:
//		return k.Public().(ed25519.PublicKey)
//	default:
//		return nil
//	}
//}

//func main() {
func doFalseHost(parentTemplate x509.Certificate, parentPriv interface{}) {
//	flag.Parse()

//	if len(*host) == 0 {
//		log.Fatalf("Missing required --host parameter")
//	}

	var priv interface{}
	var err error
	switch *ecdsaCurve {
	case "":
		if *ed25519Key {
			_, priv, err = ed25519.GenerateKey(rand.Reader)
		} else {
			//priv, err = rsa.GenerateKey(rand.Reader, *rsaBits)
			log.Fatalf("Missing required --ecdsa-curve or --ed25519 parameter")
		}
	case "P224": // nolint: goconst
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256": // nolint: goconst
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384": // nolint: goconst
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521": // nolint: goconst
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		log.Fatalf("Unrecognized elliptic curve: %q", *ecdsaCurve)
	}
	if err != nil {
		//log.Fatalf("failed to generate private key: %s", err)
		log.Fatalf("Failed to generate false private key: %v", err)
	}

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature
	// Only RSA subject keys should have the KeyEncipherment KeyUsage bits set. In
	// the context of TLS this KeyUsage is particular to RSA key exchange and
	// authentication.
	//if _, isRSA := priv.(*rsa.PrivateKey); isRSA {
	//	keyUsage |= x509.KeyUsageKeyEncipherment
	//}

	var notBefore time.Time
	if len(*validFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2006", *validFrom)
		if err != nil {
			log.Fatalf("Failed to parse creation date: %v", err)
		}
	}

	notAfter := notBefore.Add(*validFor)

	//serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	//serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	//if err != nil {
	//	log.Fatalf("Failed to generate serial number: %v", err)
	//}
	serialNumber := big.NewInt(2)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			//Organization: []string{"Acme Co"},
			CommonName:   *falseHost,
			SerialNumber: "Namecoin TLS Certificate",
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	//hosts := strings.Split(*host, ",")
	//for _, h := range hosts {
	//	if ip := net.ParseIP(h); ip != nil {
	//		template.IPAddresses = append(template.IPAddresses, ip)
	//	} else {
	//		template.DNSNames = append(template.DNSNames, h)
	template.DNSNames = append(template.DNSNames, *falseHost)
	//	}
	//}

	//if *isCA {
	//	template.IsCA = true
	//	template.KeyUsage |= x509.KeyUsageCertSign
	//}

	//derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &parentTemplate, publicKey(priv), parentPriv)
	if err != nil {
		//log.Fatalf("Failed to create certificate: %v", err)
		log.Fatalf("Failed to create false certificate: %v", err)
	}

	//certOut, err := os.Create("cert.pem")
	certOut, err := os.Create("falseCert.pem")
	if err != nil {
		//log.Fatalf("Failed to open cert.pem for writing: %v", err)
		log.Fatalf("Failed to open falseCert.pem for writing: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		//log.Fatalf("Failed to write data to cert.pem: %v", err)
		log.Fatalf("Failed to write data to falseCert.pem: %v", err)
	}
	if err := certOut.Close(); err != nil {
		//log.Fatalf("Error closing cert.pem: %v", err)
		log.Fatalf("Error closing falseCert.pem: %v", err)
	}
	//log.Print("wrote cert.pem\n")
	log.Print("wrote falseCert.pem\n")

	//keyOut, err := os.OpenFile("key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	keyOut, err := os.OpenFile("falseKey.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		//log.Fatalf("Failed to open key.pem for writing: %v", err)
		log.Fatalf("Failed to open falseKey.pem for writing: %v", err)
		return
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		//log.Fatalf("Failed to write data to key.pem: %v", err)
		log.Fatalf("Failed to write data to falseKey.pem: %v", err)
	}
	if err := keyOut.Close(); err != nil {
		//log.Fatalf("Error closing key.pem: %v", err)
		log.Fatalf("Error closing falseKey.pem: %v", err)
	}
	//log.Print("wrote key.pem\n")
	log.Print("wrote falseKey.pem\n")
}
