# Attested OHTTP Client
This repository 

## Prerequisites 

1. An AzureML endpoint with a confidential whisper model. 
2. Docker 

## Using pre-built image
You can use pre-built attested OHTTP container images to run an inferencing request. 

To run inferencing using a pre-packaged audio file, 
```
export KMS_URL=https://accconfinferencedebug.confidential-ledger.azure.com
docker run mcr.microsoft.com/attested-ohttp-client:latest \
  ${SCORING_ENDPOINT} -F "file=/examples/audio.mp3" --kms-url=${KMS_URL}
```
To run inferencing using your own audio file, 
```
export KMS_URL=https://accconfinferencedebug.confidential-ledger.azure.com
export INPUT=<path to your input file>
export MOUNTED_INPUT=/examples/sample.mp3
docker run mcr.microsoft.com/attested-ohttp-client:latest --volume ${INPUT}:${MOUNTED_INPUT}\
  ${SCORING_ENDPOINT} -F "file=${MOUNTED_INPUT}" --kms-url=${KMS_URL}
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