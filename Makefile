all: SecretScanner

$(PWD)/agent-plugins-grpc/proto/*.proto:
	$(PWD)/bootstrap.sh

$(PWD)/agent-plugins-grpc/proto/*.go: $(PWD)/agent-plugins-grpc/proto/*.proto
	(cd agent-plugins-grpc && make go)

clean:
	-(cd agent-plugins-grpc && make clean)
	-rm ./SecretScanner

SecretScanner: $(PWD)/**/*.go $(PWD)/agent-plugins-grpc/proto/*.go
	go build -buildvcs=false -v .

.PHONY: clean
