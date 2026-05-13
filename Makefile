.PHONY: all build-server build-windows build-android test lint clean

all: build-server

build-server:
	cd server/userspace && go build -o ../../bin/wireguard-oe-server .

build-windows:
	cd client-windows && go build -o ../bin/wireguard-oe-client.exe .

build-android:
	cd client-android && ./gradlew assembleRelease

test:
	cd common && go test -v ./...
	cd server/userspace && go test -v ./...
	cd client-windows && go test -v ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/
