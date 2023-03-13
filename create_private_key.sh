#!/usr/bin/env bash
#
# This generates a RSA 2048 key using OpenSSL. When running this in production
# we should use a 4096 key instead.

set -e

openssl genrsa -out private_key.pem 2048
