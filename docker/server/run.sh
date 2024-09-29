#!/bin/bash

if [[ -z ${TARGET} ]]; then
  echo "No TARGET defined"
  exit 1
fi

CMD="/usr/local/bin/ohttp-server --target $TARGET"

if [[ -z ${INSTANCE_SPECIFIC_KEY} ]]; then
   CMD="$CMD --attest"
fi

if [[ ${MAA_URL} ]]; then 
  CMD="$CMD --maa_url ${MAA_URL}"
fi

if [[ ${KMS_URL} ]]; then 
  CMD="$CMD --kms_url ${KMS_URL}"
fi

# Run OHTTP server
`$CMD`