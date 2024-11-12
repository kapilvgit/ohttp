#!/bin/bash

export MODEL=whisper_aoai

# Script to run make 10 times in parallel
for i in {1..10}
do
    echo "$i"
done | parallel -j 10 "make run-client-kms-aoai-apim-token-test"
