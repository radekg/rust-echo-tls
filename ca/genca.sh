#!/bin/bash

CA_NAME=${CA_NAME:-rs}

set -eu

base="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

mkdir -p "${base}/${CA_NAME}/out/"
pushd "${base}/${CA_NAME}/out/"

if [ ! -f "${CA_NAME}.pem" ]; then
    echo " ::> generating root CA..."
    cfssl gencert -initca "${base}/${CA_NAME}/root.json" | cfssljson -bare "${CA_NAME}"
    rm "${CA_NAME}.csr"
else
    echo " ::> root CA found"
fi

if [ ! -f "${CA_NAME}-intermediate.pem" ]; then
    echo " ::> creating intermediate CA..."
    cfssl gencert -initca "${base}/${CA_NAME}/intermediate.json" | cfssljson -bare "${CA_NAME}-intermediate"
    cfssl sign -ca "${CA_NAME}.pem" -ca-key "${CA_NAME}-key.pem" \
        -config "${base}/${CA_NAME}/profiles.json" \
        -profile intermediate_ca \
        "${CA_NAME}-intermediate.csr" | cfssljson -bare "${CA_NAME}-intermediate"
    rm "${CA_NAME}-intermediate.csr"
else
    echo " ::> intermediate CA found"
fi

# generate server certificate:
if [ ! -f "${CA_NAME}-server.pem" ]; then
    echo " ::> creating server certificate..."
    cfssl gencert -initca "${base}/${CA_NAME}/server.json" | cfssljson -bare "${CA_NAME}-server"
    cfssl sign -ca "${CA_NAME}-intermediate.pem" -ca-key "${CA_NAME}-intermediate-key.pem" \
        -config "${base}/${CA_NAME}/profiles.json" \
        -profile server \
        "${CA_NAME}-server.csr" | cfssljson -bare "${CA_NAME}-server"
    rm "${CA_NAME}-server.csr"
else
    echo " ::> server certificate found"
fi

# generate client certificate:
if [ ! -f "${CA_NAME}-client.pem" ]; then
    echo " ::> creating client certificate..."
    cfssl gencert -initca "${base}/${CA_NAME}/client.json" | cfssljson -bare "${CA_NAME}-client"
    cfssl sign -ca "${CA_NAME}-intermediate.pem" -ca-key "${CA_NAME}-intermediate-key.pem" \
        -config "${base}/${CA_NAME}/profiles.json" \
        -profile client \
        "${CA_NAME}-client.csr" | cfssljson -bare "${CA_NAME}-client"
    rm "${CA_NAME}-client.csr"
else
    echo " ::> client certificate found"
fi

# The order matters.
# Trust chain is the CA file:
cat "${CA_NAME}-intermediate.pem" > "${CA_NAME}-trust-chain.pem"
cat "${CA_NAME}.pem" >> "${CA_NAME}-trust-chain.pem"

# The server requires a certificate with its trust chain in a single file:
cat "${CA_NAME}-server.pem" > "${CA_NAME}-server-chain.pem"
cat "${CA_NAME}-intermediate.pem" >> "${CA_NAME}-server-chain.pem"
cat "${CA_NAME}.pem" >> "${CA_NAME}-server-chain.pem"
