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

	caChainOut, err := os.Create("caChain.pem")
	if err != nil {
		log.Fatalf("Failed to open caChain.pem for writing: %v", err)
	}

	if *useAIA || *parentChain != "" || *grandparentChain != "" {
		_, err = chainOut.WriteString("\n\n")
		if err != nil {
			log.Fatalf("Failed to write CA cert padding to chain.pem: %v", err)
		}

		parentToRead := "caCert.pem"
		if *parentChain != "" {
			parentToRead = *parentChain
		}

		caCert, err := ioutil.ReadFile(parentToRead)
		if err != nil {
			log.Fatalf("Failed to read %s: %v", parentToRead, err)
		}

		_, err = chainOut.Write(caCert)
		if err != nil {
			log.Fatalf("Failed to write CA cert to chain.pem: %v", err)
		}

		_, err = caChainOut.Write(caCert)
		if err != nil {
			log.Fatalf("Failed to write CA cert to caChain.pem: %v", err)
		}
	}

	if *grandparentChain != "" {
		_, err = chainOut.WriteString("\n\n")
		if err != nil {
			log.Fatalf("Failed to write grandparent CA cert padding to chain.pem: %v", err)
		}

		_, err = caChainOut.WriteString("\n\n")
		if err != nil {
			log.Fatalf("Failed to write grandparent CA cert padding to caChain.pem: %v", err)
		}

		grandparentCert, err := ioutil.ReadFile(*grandparentChain)
		if err != nil {
			log.Fatalf("Failed to read %s: %v", *grandparentChain, err)
		}

		_, err = chainOut.Write(grandparentCert)
		if err != nil {
			log.Fatalf("Failed to write grandparent CA cert to chain.pem: %v", err)
		}

		_, err = caChainOut.Write(grandparentCert)
		if err != nil {
			log.Fatalf("Failed to write grandparent CA cert to caChain.pem: %v", err)
		}
	}

	if err := chainOut.Close(); err != nil {
		log.Fatalf("Error closing chain.pem: %v", err)
	}
	log.Print("wrote chain.pem\n")

	if err := caChainOut.Close(); err != nil {
		log.Fatalf("Error closing caChain.pem: %v", err)
	}
	log.Print("wrote caChain.pem\n")
}
