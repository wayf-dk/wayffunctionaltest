# gosaml

Wayffunctionaltest is a library for making programs that tests the WAYF hub + the BIRK mass-IdP proxy.

It uses the WAYF gosaml library.

I "contains" a SP, an IdP and a "browser" in order to automatically test the functionality of the hub and the BIRK service.

Required packages on Ubuntu 14.04 LTS
- pkg-config
- libxml2-dev

# Simple install guide
mkdir -p wft/src
cd wft
export GOPATH=$PWD
export GOBIN=$PWD/bin
cd src
git clone https://github.com/wayf-dk/wayffunctionaltest.git
glide install
