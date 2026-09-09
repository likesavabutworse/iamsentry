BINARY := iamsentry
BIN_DIR := bin

.PHONY: all build test vet fmt fmt-check clean install

all: fmt-check vet test build

build:
	go build -o $(BIN_DIR)/$(BINARY) ./cmd/iamsentry

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed on:"; echo "$$unformatted"; exit 1; \
	fi

install:
	go install ./cmd/iamsentry

clean:
	rm -rf $(BIN_DIR)
