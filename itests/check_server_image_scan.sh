#!/bin/bash

RET=0

_term() {
    kill $PID
    exit $RET
}
trap _term TERM INT

./SecretScanner --socket-path /tmp/test.sock&
PID=$!

sleep 2

COUNT=`grpcurl -plaintext -import-path ./agent-plugins-grpc/proto -proto secret_scanner.proto -d '{"image": {"name": "node:8.11"}}' -unix '/tmp/test.sock' secret_scanner.SecretScanner/FindSecretInfo | jq '.secrets[].imageLayerId' | wc -l`

if [ "$COUNT" == "47" ]; then
    RET=0
else
    RET=1
fi

_term
