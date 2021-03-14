// Copyright 2015-2021 Jeremy Rand. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"io/ioutil"
	"log"

	x509_compressed "github.com/namecoin/x509-compressed/x509"
)

func writeJSONTLSA(priv interface{}) {
	pubBytes, err := x509_compressed.MarshalPKIXPublicKey(publicKey(priv))
	if err != nil {
		log.Fatalf("Failed to marshal CA public key: %v", err)
	}

	// See the IANA DANE Parameters registry.
	tlsa := make([]interface{}, 4)
	tlsa[0] = 2 // DANE-TA
	tlsa[1] = 1 // SPKI
	tlsa[2] = 0 // Full
	tlsa[3] = pubBytes

	tlsaBytes, err := json.Marshal(tlsa)
	if err != nil {
		log.Fatalf("Failed to marshal Namecoin record: %v", err)
	}

	err = ioutil.WriteFile("namecoin.json", tlsaBytes, 0600)
	if err != nil {
		log.Fatalf("Failed to write data to namecoin.json: %v", err)
	}

	log.Print("wrote namecoin.json")
}
