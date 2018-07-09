[![Go Report Card](https://goreportcard.com/badge/github.com/wayf-dk/wayffunctionaltest)](https://goreportcard.com/report/github.com/wayf-dk/wayffunctionaltest)
# Wayffunctionaltest

Wayffunctionaltest is a library for making programs that tests the WAYF hub + the BIRK mass-IdP proxy.

It uses the WAYF gosaml library.

I "contains" a SP, an IdP and a "browser" in order to automatically test the functionality of the hub and the BIRK service.

Required packages on Ubuntu 14.04 LTS
- pkg-config
- libxml2-dev

# Simple install guide
1. mkdir -p wft/src
2. cd wft
3. export GOPATH=$PWD
4. export GOBIN=$PWD/bin
5. cd src
6. git clone https://github.com/wayf-dk/wayffunctionaltest.git
7. glide install
8. go test -c -o ../../wayffunctionaltest.test
