// nolint: gofmt, goimports

// Copyright 2009 The Go Authors. All rights reserved.
// Dehydrated certificate modifications Copyright 2015-2017 Jeremy Rand. All
// rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.


// Generate a self-signed X.509 certificate for a TLS server. Outputs to
// 'cert.pem' and 'key.pem' and will overwrite existing files.

// This code has been modified from the stock Go code to generate
// "dehydrated certificates", suitable for inclusion in a Namecoin name.

// Last rebased against Go 1.14.
// Future rebases need to rebase all of the main, parent, aiaparent, and
// falseHost flows.

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	//"net"
	"os"
	//"strings"
	"time"

	"github.com/namecoin/ncdns/certdehydrate"
)

var (
	//host       = flag.String("host", "", "Comma-separated hostnames and IPs to generate a certificate for")
	host       = flag.String("host", "", "Hostname to generate a certificate for (only use one)")
	validFrom  = flag.String("start-date", "", "Creation date formatted as Jan 1 15:04:05 2011")
	validFor   = flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
	//isCA       = flag.Bool("ca", false, "whether this cert should be its own Certificate Authority")
	//rsaBits    = flag.Int("rsa-bits", 2048, "Size of RSA key to generate. Ignored if --ecdsa-curve is set")
	//ecdsaCurve = flag.String("ecdsa-curve", "", "ECDSA curve to use to generate a key. Valid values are P224, P256 (recommended), P384, P521")
	ecdsaCurve = flag.String("ecdsa-curve", "P256", "ECDSA curve to use to generate a key. Valid values are P224, P256 (recommended), P384, P521")
	ed25519Key = flag.Bool("ed25519", false, "Generate an Ed25519 key")
	falseHost  = flag.String("false-host", "", "(Optional) Generate a false cert for this host; used to test x.509 implementations for safety regarding handling of the CA flag and KeyUsage")
	useCA      = flag.Bool("use-ca", false, "Use a CA instead of self-signing")
	parentKey  = flag.String("parent-key", "", "(Optional) Path to existing CA private key to sign with")
	useAIA     = flag.Bool("use-aia", false, "Use AIA to chase the CA")
)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

func main() {
	flag.Parse()

	if len(*host) == 0 {
		log.Fatalf("Missing required --host parameter")
	}

	var priv interface{}
	var err error
	if *ed25519Key {
		*ecdsaCurve = ""
	}
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
		log.Fatalf("Failed to generate private key: %v", err)
	}

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

	timestampPrecision := int64(5 * 60)

	notBeforeFloored := time.Unix((notBefore.Unix()/timestampPrecision)*timestampPrecision, 0)
	notAfterFloored := time.Unix((notAfter.Unix()/timestampPrecision)*timestampPrecision, 0)

	//serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	//serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	// Serial components
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(publicKey(priv))
	if err != nil {
		log.Fatalf("failed to marshal public key: %s", err)
	}
	pubkeyB64 := base64.StdEncoding.EncodeToString(pubkeyBytes)
	notBeforeScaled := notBeforeFloored.Unix() / timestampPrecision
	notAfterScaled := notAfterFloored.Unix() / timestampPrecision

	// Calculate serial
	serialDehydrated := certdehydrate.DehydratedCertificate{
		PubkeyB64:       pubkeyB64,
		NotBeforeScaled: notBeforeScaled,
		NotAfterScaled:  notAfterScaled,
	}
	serialNumber := big.NewInt(1)
	serialNumberBytes, err := serialDehydrated.SerialNumber(*host)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}
	serialNumber.SetBytes(serialNumberBytes)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			//Organization: []string{"Acme Co"},
			CommonName:   *host,
			SerialNumber: "Namecoin TLS Certificate",
		},
		//NotBefore: notBefore,
		NotBefore: notBeforeFloored,
		//NotAfter:  notAfter,
		NotAfter:  notAfterFloored,

		// x509.KeyUsageKeyEncipherment is used for RSA key exchange,
		// but not DHE/ECDHE key exchange.  Since everyone should be
		// using ECDHE (due to forward secrecy), we disallow
		// x509.KeyUsageKeyEncipherment in our template.
		//KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	//hosts := strings.Split(*host, ",")
	//for _, h := range hosts {
	//	if ip := net.ParseIP(h); ip != nil {
	//		template.IPAddresses = append(template.IPAddresses, ip)
	//	} else {
	//		template.DNSNames = append(template.DNSNames, h)
	template.DNSNames = append(template.DNSNames, *host)
	//	}
	//}

	//if *isCA {
	//	template.IsCA = true
	//	template.KeyUsage |= x509.KeyUsageCertSign
	//}

	var parent x509.Certificate
	var parentPriv interface{}

	if *useCA {
		parent, parentPriv = getParent()
	} else {
		parent, parentPriv = template, priv
	}

	//derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &parent, publicKey(priv), parentPriv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	certOut, err := os.Create("cert.pem")
	if err != nil {
		log.Fatalf("Failed to open cert.pem for writing: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("Failed to write data to cert.pem: %v", err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("Error closing cert.pem: %v", err)
	}
	log.Print("wrote cert.pem\n")

	keyOut, err := os.OpenFile("key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open key.pem for writing: %v", err)
		return
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		log.Fatalf("Failed to write data to key.pem: %v", err)
	}
	if err := keyOut.Close(); err != nil {
		log.Fatalf("Error closing key.pem: %v", err)
	}
	log.Print("wrote key.pem\n")

	if *useCA {
		log.Print("SUCCESS.  Place cert.pem and key.pem in your HTTPS server, and place the contents of \"namecoin.json\" in the \"tls\" field for \"*." + *host + "\".")
		return
	}

	parsedResult, err := x509.ParseCertificate(derBytes)
	if err != nil {
		log.Fatal("failed to parse output cert: ", err)
	}

	dehydrated, err := certdehydrate.DehydrateCert(parsedResult)
	if err != nil {
		log.Fatal("failed to dehydrate result cert: ", err)
	}

	rehydrated, err := certdehydrate.RehydrateCert(dehydrated)
	if err != nil {
		log.Fatal("failed to rehydrate result cert: ", err)
	}

	rehydratedDerBytes, err := certdehydrate.FillRehydratedCertTemplate(*rehydrated, *host)
	if err != nil {
		log.Fatal("failed to fill rehydrated result cert: ", err)
	}

	if !bytes.Equal(derBytes, rehydratedDerBytes) {
		log.Fatal("ERROR: The cert did not rehydrate to an identical form.  This is a bug; do not use the generated certificate.")
	}

	log.Print("Your Namecoin cert is: {\"d8\":", dehydrated, "}")

	log.Print("SUCCESS: The cert rehydrated to an identical form.  Place the generated files in your HTTPS server, and place the above JSON in the \"tls\" field for your Namecoin name.")

	if len(*falseHost) > 0 {
		doFalseHost(template, priv)
	}
}
