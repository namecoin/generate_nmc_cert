generate_nmc_cert
=================

generate_nmc_cert generates TLS server certificates of the form expected by Namecoin.

Building
--------

Prerequisites:

1. Ensure you have the Go tools installed.

Option A: Using Go build commands without Go modules (works on any platform with Bash; only Go 1.15-1.16.x; will not work on Go 1.17+):

1. Ensure you have the `GOPATH` environment variable set. (For those not
   familar with Go, setting it to the path to an empty directory will suffice.
   The directory will be filled with build files.)

2. Run `export GO111MODULE=off` to disable Go modules.

3. Run `go get -d -t -u github.com/namecoin/generate_nmc_cert/...`. The generate_nmc_cert source code will be
   retrieved automatically.

4. If running an old Go version, you may need to enter the `generate_nmc_cert` directory and `git checkout` an older tag, e.g. for Go 1.15.x you should checkout the `v1.14` tag.

5. Run `go get -t -u github.com/namecoin/generate_nmc_cert/...`.  generate_nmc_cert will be built. The binaries will be at `$GOPATH/bin/generate_nmc_cert`.

Option B: Using Go build commands with Go modules (works on any platform with Bash; Go 1.15+:

1. `git clone generate_nmc_cert`.

2. If running an old Go version, you may need to enter the `generate_nmc_cert` directory and `git checkout` an older tag, e.g. for Go 1.15.x you should checkout the `v1.14` tag.

3. Run the following in the generate_nmc_cert directory to set up Go modules:
   
   ~~~
   go mod init
   go mod tidy
   ~~~

4. Run `go install ./...`.  generate_nmc_cert will be built. The binaries will be at `$GOPATH/bin/generate_nmc_cert`.

Option C: Using Makefile (non-Windows platforms):

1. Run `make`. The source repository will be retrieved via `go get`
   automatically.

Licence
-------

License matches the upstream Go standard library's BSD-style license; see `LICENSE` for details.
