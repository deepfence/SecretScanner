package main

// ------------------------------------------------------------------------------
// MIT License

// Copyright (c) 2020 deepfence

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// ------------------------------------------------------------------------------

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"path"
	"runtime"
	"strconv"

	"github.com/deepfence/SecretScanner/core"
	"github.com/deepfence/SecretScanner/jobs"
	"github.com/deepfence/SecretScanner/output"
	"github.com/deepfence/SecretScanner/server"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	out "github.com/deepfence/YaraHunter/pkg/output"
	"github.com/deepfence/YaraHunter/pkg/runner"
	yaraserver "github.com/deepfence/YaraHunter/pkg/server"

	pb "github.com/deepfence/agent-plugins-grpc/srcgo"
)

const (
	PLUGIN_NAME = "SecretScanner"
)

var (
	socketPath = flag.String("socket-path", "", "The gRPC server unix socket path")
)

// Read the regex signatures from config file, options etc.
// and setup the session to start scanning for secrets
var session = core.GetSession()

type SecretsWriter interface {
	WriteJSON() error
	WriteTable() error
	GetSecrets() []output.SecretFound
	AddSecret(output.SecretFound)
}

func main() {
	log.SetOutput(os.Stderr)
	log.SetLevel(log.InfoLevel)
	log.SetReportCaller(true)
	log.SetFormatter(&log.TextFormatter{
		DisableColors: false,
		ForceColors:   true,
		FullTimestamp: true,
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			return "", " " + path.Base(f.File) + ":" + strconv.Itoa(f.Line)
		},
	})

	flag.Parse()

	if *core.GetSession().Options.Debug {
		log.SetLevel(log.DebugLevel)
	}

	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt)

	out.ScanStatusFilename = jobs.GetDfInstallDir() + "/var/log/fenced/secret-scan-log/secret_scan_log.log"
	out.ScanFilename = jobs.GetDfInstallDir() + "/var/log/fenced/secret-scan/secret_scan.log"

	runnerOpts := runner.RunnerOptions{
		SocketPath:           *socketPath,
		RulesPath:            *core.GetSession().Options.RulesPath,
		RulesListingURL:      *core.GetSession().Options.RulesListingURL,
		HostMountPath:        *core.GetSession().Options.HostMountPath,
		FailOnCompileWarning: *core.GetSession().Options.FailOnCompileWarning,
		Local:                *core.GetSession().Options.Local,
		ImageName:            *core.GetSession().Options.ImageName,
		ContainerID:          *core.GetSession().Options.ContainerID,
		ConsoleURL:           *core.GetSession().Options.ConsoleURL,
		ConsolePort:          *core.GetSession().Options.ConsolePort,
		DeepfenceKey:         *core.GetSession().Options.DeepfenceKey,
		OutFormat:            *core.GetSession().Options.OutFormat,
		FailOnHighCount:      *core.GetSession().Options.FailOnHighCount,
		FailOnMediumCount:    *core.GetSession().Options.FailOnMediumCount,
		FailOnLowCount:       *core.GetSession().Options.FailOnLowCount,
		FailOnCount:          *core.GetSession().Options.FailOnCount,
		InactiveThreshold:    *core.GetSession().Options.InactiveThreshold,
	}

	if *core.GetSession().Options.EnableUpdater {
		go runner.ScheduleYaraHunterUpdater(ctx, runnerOpts)
	}

	runner.StartYaraHunter(ctx, runnerOpts, core.GetSession().ExtractorConfig,

		func(base *yaraserver.GRPCScannerServer) server.SecretGRPCServer {
			return server.SecretGRPCServer{
				GRPCScannerServer:                base,
				UnimplementedSecretScannerServer: pb.UnimplementedSecretScannerServer{},
			}
		},
		func(s grpc.ServiceRegistrar, impl any) {
			pb.RegisterSecretScannerServer(s, impl.(pb.SecretScannerServer))
		})
}
