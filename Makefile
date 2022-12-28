all: SecretScanner

$(PWD)/agent-plugins-grpc/proto/*.proto:
	$(PWD)/bootstrap.sh

$(PWD)/agent-plugins-grpc/proto/*.go: $(PWD)/agent-plugins-grpc/proto/*.proto
	(cd agent-plugins-grpc && make go)

clean:
	-(cd agent-plugins-grpc && make clean)
	-rm ./SecretScanner

SecretScanner: $(PWD)/**/*.go $(PWD)/agent-plugins-grpc/proto/*.go
	PKG_CONFIG_PATH=/tmp/src/hyperscan/build CGO_LDFLAGS="-L /tmp/src/hyperscan/build/lib -static" CGO_CFLAGS="-I/tmp/src/hyperscan/src" go build ./main.go

.PHONY: clean
