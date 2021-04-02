build: fmt test lint
	mkdir -p bin && go build -o ./bin/cir ./cmd/cir

test:
	go test ./...

fmt:
	go fmt ./...

lint:
	golint ./...

run: build
	./bin/cir run

install-local-dev: build
	sudo cp ./bin/cir /usr/local/bin

