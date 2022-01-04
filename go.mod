module github.com/deepfence/SecretScanner

go 1.17

require (
	github.com/deepfence/agent-plugins-grpc v0.0.0
	github.com/fatih/color v1.13.0
	github.com/flier/gohs v1.1.1
	google.golang.org/grpc v1.38.0
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)

require (
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/mattn/go-colorable v0.1.9 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	golang.org/x/net v0.0.0-20211123203042-d83791d6bcd9 // indirect
	golang.org/x/sys v0.0.0-20211123173158-ef496fb156ab // indirect
	golang.org/x/text v0.3.6 // indirect
	google.golang.org/genproto v0.0.0-20210602131652-f16073e35f0c // indirect
	google.golang.org/protobuf v1.26.0 // indirect
)

replace github.com/deepfence/agent-plugins-grpc => ./agent-plugins-grpc
