#!/bin/sh

source ./gen_root_ca_keypair.sh
./gen_root_ca_cert
source ./import_root_ca_cert.sh
