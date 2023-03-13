#!/usr/bin/env bash

set -e

echo "sudo password is needed"
sudo nc -l -p 80 > my_signed_binary.bin
