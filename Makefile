NAME := trojan-prober
BUILD_DIR := build
GOBUILD := env CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -tags "full" -o $(BUILD_DIR)/$(NAME) ./src

.PHONY: all clean test

all: clean trojan-prober

test:
	go test ./src/...

clean:
	rm -rf $(BUILD_DIR)
	rm -f *.zip

trojan-prober:
	mkdir -p $(BUILD_DIR)
	$(GOBUILD)
