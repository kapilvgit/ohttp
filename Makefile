TARGET ?= http://127.0.0.1:3000

ca:
	./ohttp-server/ca.sh

run-client: ca
	cargo run --bin ohttp-client -- --trust ./ohttp-server/ca.crt \
  'https://localhost:9443/score' -i ./examples/request.txt \
  `curl -s -k https://localhost:9443/discover`

run-client2: ca
	cargo run --bin ohttp-client -- --trust ./ohttp-server/ca.crt \
  'https://localhost:9443/score' -i ./examples/request2.txt \
  `curl -s -k https://localhost:9443/discover`

run-client3: ca
	cargo run --bin ohttp-client -- --trust ./ohttp-server/ca.crt \
  'https://localhost:9443/score' -i ./examples/request3.txt \
  `curl -s -k https://localhost:9443/discover`

run-client4: ca
	cargo run --bin ohttp-client -- --trust ./ohttp-server/ca.crt \
  'https://localhost:9443/score' -i ./examples/request4.txt \
  `curl -s -k https://localhost:9443/discover`


run-client5: ca
	cargo run --bin ohttp-client -- --trust ./ohttp-server/ca.crt \
  'https://localhost:9443/score' -i ./examples/request5.txt \
  `curl -s -k https://localhost:9443/discover`

run-client6: ca
	cargo run --bin ohttp-client -- --trust ./ohttp-server/ca.crt \
  'https://localhost:9443/score' -a ./examples/whatstheweatherlike.wav \
  `curl -s -k https://localhost:9443/discover`

build-server:
	docker build -f docker/server/Dockerfile -t ohttp-server .

build-client:
	docker build -f docker/client/Dockerfile -t ohttp-client .

build-target:
	docker build -f docker/streaming/Dockerfile -t nodejs-streaming .

build: build-server build-client build-target

run-server:
	docker compose -f ./docker/docker-compose-streaming.yml up


stop-server:
	docker compose -f ./docker/docker-compose-streaming.yml stop

kill-server:
	docker compose -f ./docker/docker-compose-streaming.yml kill


# run-client10:
# 	docker run --net=host ohttp-client