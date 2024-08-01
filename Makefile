BINARY_NAME=symmecrypt

all: run

build:
	GOOS=${GOOS} GOARCH=${GOARCH} CGO_ENABLED=0 go build -o dist/${BINARY_NAME}-${GOOS}-${GOARCH} cmd/symmecrypt/main.go

test:
	go test -v -coverprofile cover.out -race ./...

run:
	go run cmd/symmecrypt/main.go

clean:
	rm -rf dist
