.PHONY: all clean build build-linux build-darwin build-windows install test quick

BINARY_NAME=shai-hulud-guard
VERSION?=1.0.0
BUILD_DIR=dist

all: clean build

clean:
	rm -rf $(BUILD_DIR)

build: clean build-linux build-darwin build-windows quick install

build-linux:
	@echo "Building for Linux..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/shai-hulud-guard
	GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/shai-hulud-guard

build-darwin:
	@echo "Building for macOS..."
	@mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/shai-hulud-guard
	GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/shai-hulud-guard

build-windows:
	@echo "Building for Windows..."
	@mkdir -p $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/shai-hulud-guard

install:
	@echo "Installing $(BINARY_NAME)..."
	go install ./cmd/shai-hulud-guard

test:
	go test -v ./...

# Build for current platform only
quick:
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/shai-hulud-guard
	@echo "Built: $(BUILD_DIR)/$(BINARY_NAME)"
