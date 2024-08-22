TARGET ?= http://127.0.0.1:3000

ca:
	./ohttp-server/ca.sh

run-client1: ca
	cargo run --bin ohttp-client -- --trust ./ohttp-server/ca.crt \
  'https://localhost:9443/score' -i ./examples/request.txt \
  `curl -s -k https://localhost:9443/discover`

run-client2: ca
	cargo run --bin ohttp-client -- --trust ./ohttp-server/ca.crt \
  'https://localhost:9443/score' -a ./examples/whatstheweatherlike.wav \
  `curl -s -k https://localhost:9443/discover`

run-client3: ca
	cargo run --bin ohttp-client -- --trust ./ohttp-server/ca.crt \
  'https://localhost:9443/score' -a ./examples/15m_gpt-has-entered-the-chat.mp3 \
  `curl -s -k https://localhost:9443/discover`

run-client4: ca
	cargo run --bin ohttp-client -- --trust ./ohttp-server/ca.crt \
  'https://localhost:9443/score' -a ./examples/audio-sample-2.mp3 \
  `curl -s -k https://localhost:9443/discover`

bs:
	docker build -f docker/server/Dockerfile -t ohttp-server .

build-client:
	docker build -f docker/client/Dockerfile -t ohttp-client .

build-target:
	docker build -f docker/streaming/Dockerfile -t nodejs-streaming .

build: build-server build-client build-target

rs:
	docker compose -f ./docker/docker-compose-streaming.yml up


stop-server:
	docker compose -f ./docker/docker-compose-streaming.yml stop

ks:
	docker compose -f ./docker/docker-compose-streaming.yml kill

# run-whisper:
#     docker run -d --gpus all -p 9000:9000 -e ASR_MODEL=base -e ASR_ENGINE=openai_whisper onerahmet/openai-whisper-asr-webservice:latest

# run-client10:
# 	docker run --net=host ohttp-client