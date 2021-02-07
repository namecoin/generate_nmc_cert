generate_nmc_cert
=================

generate_nmc_cert generates TLS server certificates of the form expected by Namecoin.

Building
--------

Prerequisites:

1. Ensure you have the Go tools installed.

Option A: Using Go build commands (works on any platform):

1. Ensure you have the GOPATH environment variable set. (For those not
   familar with Go, setting it to the path to an empty directory will suffice.
   The directory will be filled with build files.)

2. Run `go get -d -t -u github.com/namecoin/generate_nmc_cert/...`. The generate_nmc_cert source code will be
   retrieved automatically.

3. Run `go generate github.com/namecoin/x509_compressed/...`.  The compressed public key patch will be applied.

4. Run `go get -t -u github.com/namecoin/generate_nmc_cert/...`. generate_nmc_cert will be built. The binaries will be at
   $GOPATH/bin/generate_nmc_cert.

Option B: Using Makefile (non-Windows platforms):

1. Run `make`. The source repository will be retrieved via `go get`
   automatically.

Licence
-------

License matches the upstream Go standard library's BSD-style license; see `LICENSE` for details.
