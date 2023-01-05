all: SecretScanner

$(PWD)/agent-plugins-grpc/proto/*.proto:
	$(PWD)/bootstrap.sh

$(PWD)/agent-plugins-grpc/proto/*.go: $(PWD)/agent-plugins-grpc/proto/*.proto
	(cd agent-plugins-grpc && make go)

clean:
	-(cd agent-plugins-grpc && make clean)
	-rm ./SecretScanner

SecretScanner: $(PWD)/**/*.go $(PWD)/agent-plugins-grpc/proto/*.go
	go build $(GO_BUILD_EXTRA)

static:
	docker build -t static-secret-scanner -f Dockerfile-static .
	docker run -v $(PWD):/go/src/SecretScanner static-secret-scanner

.PHONY: clean static
