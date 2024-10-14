KMS ?= https://acceu-aml-504.confidential-ledger.azure.com
MAA ?= https://maanosecureboottestyfu.eus.attest.azure.net

# MODEL can be whisper_opensource, whisper_aoai or whisper_aoai_local
MODEL ?= whisper_opensource
ifeq ($(MODEL), whisper_opensource)
	TARGET ?= http://127.0.0.1:3000
	TARGET_PATH ?= '/whisper'
	SCORING_ENDPOINT ?= 'http://localhost:9443/score'
else ifeq ($(MODEL), whisper_aoai_local)
	TARGET ?= http://127.0.0.1:5001
	TARGET_PATH ?= '/v1/engines/whisper/audio/transcriptions'
	SCORING_ENDPOINT ?= 'http://localhost:9443/score'
else ifeq ($(MODEL), whisper_aoai)
	TARGET ?= http://127.0.0.1:5002
	TARGET_PATH ?= '/v1/engines/whisper/audio/transcriptions'
	DEPLOYMENT ?= 'arthig-deploy16'
	SCORING_ENDPOINT ?= 'https://arthig-ep.eastus2.inference.ml.azure.com/score'
else
	echo "Unknown model"
endif
	
INPUT ?= ./examples/audio.mp3
INJECT_HEADERS ?= openai-internal-enableasrsupport

build-whisper:
	docker build -f docker/whisper/Dockerfile -t whisper-api ./docker/whisper

build-server:
	docker build -f docker/server/Dockerfile -t ohttp-server .

build-client:
	docker build -f docker/client/Dockerfile -t ohttp-client .

build-streaming:
	docker build -f docker/streaming/Dockerfile -t nodejs-streaming .

build: build-server build-client build-streaming build-whisper

run-server:
	cargo run --bin ohttp-server -- --target ${TARGET}

run-server-attest:
	cargo run --bin ohttp-server -- --certificate ./ohttp-server/server.crt \
		--key ./ohttp-server/server.key --target ${TARGET} \
		--attest --maa_url ${MAA} --kms_url ${KMS}

run-server-container: 
	docker compose -f ./docker/docker-compose-server.yml up

run-server-container-attest: 
	docker run --privileged -e TARGET=${TARGET} -e MAA_URL=${MAA} -e INJECT_HEADERS=${INJECT_HEADERS} --net=host --mount type=bind,source=/sys/kernel/security,target=/sys/kernel/security  --device /dev/tpmrm0  ohttp-server

run-whisper:
	docker run --network=host whisper-api 

run-whisper-faster: 
	docker run --network=host fedirz/faster-whisper-server:latest-cuda

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
	
run-client-kms: service-cert 
	RUST_LOG=info cargo run --bin ohttp-client -- $(SCORING_ENDPOINT)\
  --target-path ${TARGET_PATH} -F "file=@${INPUT}" \
  --kms-cert ./service_cert.pem 

run-client-local:
	RUST_LOG=info cargo run --bin ohttp-client -- $(SCORING_ENDPOINT)\
  --target-path ${TARGET_PATH} -F "file=@${INPUT}" \
  -H "api-key: test123" --config `curl -s http://localhost:9443/discover` 

run-client-kms-aoai-local: service-cert 
	RUST_LOG=info cargo run --bin ohttp-client -- $(SCORING_ENDPOINT)\
  --target-path ${TARGET_PATH} -F "file=@${INPUT}" \
  --kms-cert ./service_cert.pem \
  -O 'openai-internal-enableasrsupport:true' -H 'openai-internal-enableasrsupport:true'

run-client-kms-aoai: service-cert 
	RUST_LOG=info cargo run --bin ohttp-client -- $(SCORING_ENDPOINT) \
  --target-path ${TARGET_PATH} -F "file=@${INPUT}" -F "response_format=json" -F "language=en" \
  --kms-cert ./service_cert.pem \
  -H 'openai-internal-enableasrsupport:true' -O 'openai-internal-enableasrsupport:true' -O 'azureml-model-deployment:$(DEPLOYMENT)' -T ${TOKEN}

run-client-container:
	docker run --privileged --net=host -e TARGET=${SCORING_ENDPOINT} \
	-e TARGET_PATH=${TARGET_PATH} -e KMS_URL=${KMS} \
	-e INPUT=${INPUT} ohttp-client

run-client-container-it:
	docker run -it --privileged --net=host -e TARGET=${SCORING_ENDPOINT} \
	-e TARGET_PATH=${TARGET_PATH} -e KMS_URL=${KMS} \
	-e INPUT=${INPUT} ohttp-client bash
