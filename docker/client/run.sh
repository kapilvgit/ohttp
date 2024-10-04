#!/bin/bash

if [[ -z ${TARGET} ]]; then
  echo "No TARGET defined"
  exit 1
fi

if [[ -z ${TARGET_PATH} ]]; then
  echo "No TARGET_PATH defined"
  exit 1
fi

if [[ -z ${KMS_URL} ]]; then
  echo "No KMS_URL defined"
  exit 1
fi

if [[ -z ${INPUT} ]]; then
  echo "No INPUT defined"
  exit 1
fi

# Obtain KMS service certificate
curl -s -k ${KMS_URL}/node/network | jq -r .service_certificate > /tmp/service_cert.pem

RUST_LOG=info /usr/local/bin/ohttp-client ${TARGET}/score \
  --target-path ${TARGET_PATH} -F "file=@${INPUT}" \
  --kms-url ${KMS_URL} --kms-cert /tmp/service_cert.pem 
