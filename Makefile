all: SecretScanner

bootstrap:
	$(PWD)/bootstrap.sh

clean:
	-rm ./SecretScanner

SecretScanner: $(PWD)/**/*.go $(PWD)/agent-plugins-grpc/**/*.go
	go mod tidy -v
	go mod vendor
	go build -buildvcs=false -v .

.PHONY: clean bootstrap
