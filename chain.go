// Copyright 2015-2021 Jeremy Rand. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"io/ioutil"
	"log"
	"os"
)

func writeChain() {
	chainOut, err := os.Create("chain.pem")
	if err != nil {
		log.Fatalf("Failed to open chain.pem for writing: %v", err)
	}

	leafCert, err := ioutil.ReadFile("cert.pem")
	if err != nil {
		log.Fatalf("Failed to read cert.pem: %v", err)
	}

	_, err = chainOut.Write(leafCert)
	if err != nil {
		log.Fatalf("Failed to write end-entity cert to chain.pem: %v", err)
	}

	if *useAIA {
		_, err = chainOut.WriteString("\n\n")
		if err != nil {
			log.Fatalf("Failed to write CA cert padding to chain.pem: %v", err)
		}

		caCert, err := ioutil.ReadFile("caCert.pem")
		if err != nil {
			log.Fatalf("Failed to read caCert.pem: %v", err)
		}

		_, err = chainOut.Write(caCert)
		if err != nil {
			log.Fatalf("Failed to write CA cert to chain.pem: %v", err)
		}
	}

	if err := chainOut.Close(); err != nil {
		log.Fatalf("Error closing chain.pem: %v", err)
	}
	log.Print("wrote chain.pem\n")
}
