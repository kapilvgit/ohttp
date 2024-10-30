# Attested OHTTP Client
This repository contains a reference implementation of an attested OHTTP client for 
Azure AI confidential inferencing.

## Prerequisites 

1. An AzureML endpoint with a confidential whisper model. 
2. Docker 

## Using pre-built image
You can use pre-built attested OHTTP container images to send an inferencing request. 

Set the inferencing endpoint and accessk key as follows.
```
export TARGET_URI=<URL for your endpoint>
export TARGET_PATH=/v1/engines/whisper/audio/translations
export KEY=<key for accessing the endpoint>
```

Run inferencing using a pre-packaged audio file. 
```
export KMS_URL=https://accconfinferencedebug.confidential-ledger.azure.com
docker run -e KMS_URL=${KMS_URL} mcr.microsoft.com/attested-ohttp-client:latest \
  ${TARGET_URI} --target-path ${TARGET_PATH} -F "file=@/examples/audio.mp3" \
  -O "api-key: ${KEY}" -F "response_format=json"
```

Run inferencing using your own audio file by mounting the file into the container.
```
export KMS_URL=https://accconfinferencedebug.confidential-ledger.azure.com
export INPUT_PATH=<path to your input file>
export MOUNTED_PATH=/examples/audio.mp3
docker run -e KMS_URL=${KMS_URL} --volume ${INPUT_PATH}:${MOUNTED_PATH} \
  mcr.microsoft.com/attested-ohttp-client:latest \
  ${TARGET_URI} --target-path ${TARGET_PATH} -F "file=@${MOUNTED_INPUT}" \
  -O "api-key ${KEY}" -F "response_format=json"
```

## Building your own container image

You can build you own container image using code in this repository. First, clone the repository. 
```
git clone https://github.com/microsoft/attested-ohttp-client
```

Next, build the docker image. 

```
docker build -f docker/Dockerfile -t attested-ohttp-client .
```