all: SecretScanner

clean:
	-rm ./SecretScanner

SecretScanner: $(PWD)/**/*.go $(PWD)/agent-plugins-grpc/proto/*.go
	$(PWD)/bootstrap.sh
	go mod tidy -v
	go mod vendor
	go build -buildvcs=false -v .

.PHONY: clean
