.PHONY: build test clean run

BINARY := bin/sigwatch

build:
	go build -o $(BINARY) ./cmd/sigwatch

test:
	go test ./...

clean:
	rm -rf bin/

run: build
	./$(BINARY) $(ARGS)
