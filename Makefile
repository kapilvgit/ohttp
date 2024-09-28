KMS ?= https://acceu-aml-504.confidential-ledger.azure.com
MAA ?= https://maanosecureboottestyfu.eus.attest.azure.net
#TARGET ?= https://arthig-ep.eastus2.inference.ml.azure.com/score
TARGET ?= http://127.0.0.1:5001
TARGET_PATH ?= '/v1/engines/whisper/audio/transcriptions'
INPUT ?= ./examples/audio.mp3


ca:
	./ohttp-server/ca.sh

build-whisper:
	docker build -f docker/whisper/Dockerfile -t whisper-api ./docker/whisper

build-server: ca
	docker build -f docker/server/Dockerfile -t ohttp-server .

build-client:
	docker build -f docker/client/Dockerfile -t ohttp-client .

build-streaming:
	docker build -f docker/streaming/Dockerfile -t nodejs-streaming .

build: build-server build-client build-streaming build-whisper

run-server: ca
	cargo run --bin ohttp-server -- --certificate ./ohttp-server/server.crt \
		--key ./ohttp-server/server.key --target ${TARGET} 

run-server-attest: ca
	cargo run --bin ohttp-server -- --certificate ./ohttp-server/server.crt \
		--key ./ohttp-server/server.key --target ${TARGET} \
		--attest --maa_url ${MAA} --kms_url ${KMS}

run-server-container: 
	docker run --privileged -e TARGET=${TARGET}  --net=host --mount type=bind,source=/sys/kernel/security,target=/sys/kernel/security  --device /dev/tpmrm0  ohttp-server

run-whisper:
	docker run --network=host whisper-api 

run-server-streaming:
	docker compose -f ./docker/docker-compose-streaming.yml up

run-server-whisper:
	docker compose -f ./docker/docker-compose-whisper.yml up

run-server-faster:
	docker compose -f ./docker/docker-compose-faster-whisper.yml up

service-cert:
	curl -s -k ${KMS}/node/network | jq -r .service_certificate > service_cert.pem

verify-quote:
	verify_quote.sh ${KMS} --cacert service_cert.pem
	
run-client-kms: ca service-cert verify-quote
	cargo run --bin ohttp-client -- --trust ./ohttp-server/ca.crt \
  'http://localhost:9443/score' --target-path ${TARGET_PATH} -i ${INPUT} \
  --kms-cert ./service_cert.pem 

run-client-local: ca
	cargo run --bin ohttp-client -- --trust ./ohttp-server/ca.crt \
  'http://localhost:9443/score' --target-path ${TARGET_PATH} -i ${INPUT} \
  --config `curl -s -k http://localhost:9443/discover` --api-key test123

