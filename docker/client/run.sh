#!/bin/bash

if [[ -z ${TARGET_PATH} ]]; then
  echo "No TARGET defined"
  exit 1
fi

# Generate certificate for TLS
/usr/local/bin/ca.sh

# Obtain KMS service certificate
curl -s -k https://acceu-aml-504.confidential-ledger.azure.com/node/network | jq -r .service_certificate > service_cert.pem

# Get list of public keys
curl --cacert service_cert.pem https://acceu-aml-504.confidential-ledger.azure.com/listpubkeys > keys.json

# Run OHTTP client
/usr/local/bin/ohttp-client --trust /usr/local/bin/ca.crt \
  'https://100.64.3.79:9443/score' --target-path ${TARGET_PATH} -i ./examples/audio.mp3 \
   --config `curl -s -k https://100.64.3.79:9443/discover`