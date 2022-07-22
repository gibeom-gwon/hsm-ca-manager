#!/bin/sh

pkcs11-tool -l --write-object root_ca.der --type cert --id 10
