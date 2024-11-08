KMS ?= https://accconfinferencedebug.confidential-ledger.azure.com
MAA ?= https://confinfermaaeus2test.eus2.test.attest.azure.net

# MODEL can be whisper_opensource, whisper_aoai or whisper_aoai_local
MODEL ?= whisper_opensource
ifeq ($(MODEL), whisper_opensource)
	export TARGET ?= http://127.0.0.1:3000
	export TARGET_PATH ?= '/whisper'
	export SCORING_ENDPOINT ?= 'http://localhost:9443/score'
else ifeq ($(MODEL), whisper_aoai_local)
	TARGET ?= http://127.0.0.1:5001
	TARGET_PATH ?= '/v1/engines/whisper/audio/transcriptions'
	SCORING_ENDPOINT ?= 'http://localhost:9443/score'
else ifeq ($(MODEL), whisper_aoai)
	TARGET ?= http://127.0.0.1:5002
	TARGET_PATH ?= '/v1/engines/whisper/audio/translations'
	DEPLOYMENT ?= 'arthig-deploy20'
	SCORING_ENDPOINT ?= 'https://arthig-ep.eastus2.inference.ml.azure.com/score'
else
	echo "Unknown model"
endif
	
export INPUT ?= ${PWD}/examples/audio.mp3
export MOUNTED_INPUT ?= /examples/audio.mp3
export INJECT_HEADERS ?= openai-internal-enableasrsupport
export DETACHED ?= -d

# Build commands

build-server:
	cargo build --bin ohttp-server

build-client:
	cargo build --bin ohttp-client

build-whisper-container:
	docker build -f docker/whisper/Dockerfile -t whisper-api ./docker/whisper

build-server-container:
	docker build -f docker/server/Dockerfile -t ohttp-server .

build-client-container:
	docker build -f docker/client/Dockerfile -t ohttp-client .

build: build-server-container build-client-container build-whisper-container

format-checks:
	cargo fmt --all -- --check --config imports_granularity=Crate
	cargo clippy --tests --no-default-features --features rust-hpke,client,server

# Local server deployments

run-server-kms:
	cargo run --bin ohttp-server -- --target ${TARGET} \
		--maa-url ${MAA} --kms-url ${KMS}

# Containerized server deployments

run-server-container: 
	docker compose -f ./docker/docker-compose-server.yml up

run-server-container-cvm: 
	docker run --privileged --net=host \
	-e TARGET=${TARGET} -e MAA_URL=${MAA} -e KMS_URL=${KMS}/app/key -e INJECT_HEADERS=${INJECT_HEADERS} \
	--mount type=bind,source=/sys/kernel/security,target=/sys/kernel/security \
	--device /dev/tpmrm0  ohttp-server

run-server-container-cvm-cluster: 
	docker run --privileged --net=host \
	-e TARGET=${TARGET} -e INJECT_HEADERS=${INJECT_HEADERS} \
	--mount type=bind,source=/sys/kernel/security,target=/sys/kernel/security \
	--device /dev/tpmrm0  ohttp-server

# Whisper deployments

run-whisper:
	docker run --network=host whisper-api 

run-whisper-faster: 
	docker run --network=host fedirz/faster-whisper-server:latest-cuda

run-server-whisper:
	docker compose -f ./docker/docker-compose-whisper.yml up ${DETACHED}

run-server-faster:
	docker compose -f ./docker/docker-compose-faster-whisper.yml up

service-cert:
	curl -s -k ${KMS}/node/network | jq -r .service_certificate > service_cert.pem

verify-quote:
	verify_quote.sh ${KMS} --cacert service_cert.pem

# Local client deployments

run-client:
	RUST_LOG=info cargo run --bin ohttp-client -- $(SCORING_ENDPOINT) \
  --target-path ${TARGET_PATH} -F "file=@${INPUT}" \
  --config `curl -s http://localhost:9443/discover` 

run-client-kms: service-cert 
	RUST_LOG=info cargo run --bin ohttp-client -- $(SCORING_ENDPOINT) \
  --target-path ${TARGET_PATH} -F "file=@${INPUT}" \
  --kms-url ${KMS} --kms-cert ./service_cert.pem 

run-client-kms-aoai: service-cert 
	RUST_LOG=info cargo run --bin ohttp-client -- $(SCORING_ENDPOINT) \
	--target-path ${TARGET_PATH} -F "file=@${INPUT}" \
	--kms-url ${KMS} --kms-cert ./service_cert.pem \
	-O 'openai-internal-enableasrsupport:true' -H 'openai-internal-enableasrsupport:true'

run-client-kms-aoai-token: service-cert 
	RUST_LOG=info cargo run --bin ohttp-client -- $(SCORING_ENDPOINT) \
	--target-path ${TARGET_PATH} -F "file=@${INPUT}" -F "response_format=json" -F "language=en" \
	--kms-url ${KMS} --kms-cert ./service_cert.pem \
	-H 'openai-internal-enableasrsupport:true' -O 'openai-internal-enableasrsupport:true' \
	-O 'azureml-model-deployment:$(DEPLOYMENT)' -O 'authorization: Bearer ${TOKEN}'

run-client-kms-aoai-apim-token: service-cert
	RUST_LOG=info cargo run --bin ohttp-client -- ${APIM_ENDPOINT} \
	--target-path ${TARGET_PATH} -F "file=@${INPUT}" -F "response_format=json" \
	--kms-url ${KMS} --kms-cert ./service_cert.pem -O 'api-key: ${API_KEY}'

# Containerized client deployments

run-client-container:
	docker run --net=host --volume ${INPUT}:${MOUNTED_INPUT} \
	ohttp-client $(SCORING_ENDPOINT) -F "file=@${MOUNTED_INPUT}" --target-path ${TARGET_PATH}

run-client-container-kms:
	docker run --net=host --volume ${INPUT}:${MOUNTED_INPUT} -e KMS_URL=${KMS} \
	ohttp-client ${SCORING_ENDPOINT} -F "file=@${MOUNTED_INPUT}" --target-path ${TARGET_PATH}

run-client-container-it:
	docker run -it --privileged --net=host -it --entrypoint=/bin/bash ohttp-client

run-client-container-aoai:
	docker run --volume ${INPUT}:${MOUNTED_INPUT} -e KMS_URL=${KMS} \
	ohttp-client ${SCORING_ENDPOINT} -F "file=@${MOUNTED_INPUT}" --target-path ${TARGET_PATH} \
	-O "api-key: ${API_KEY}" -F "response_format=json"