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
	"fmt"
	"os"
	"os/signal"
	"path"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/deepfence/SecretScanner/core"
	"github.com/deepfence/SecretScanner/jobs"
	"github.com/deepfence/SecretScanner/output"
	"github.com/deepfence/SecretScanner/scan"
	"github.com/deepfence/SecretScanner/server"
	"github.com/deepfence/golang_deepfence_sdk/utils/tasks"
	"github.com/deepfence/match-scanner/pkg/config"
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

func runOnce(ctx context.Context, filters config.Filters, format string) {
	var result SecretsWriter
	var err error
	node_type := ""
	node_id := ""
	var nodeType scan.ScanType

	// Scan container image for secrets
	if len(*session.Options.ImageName) > 0 {
		node_type = "image"
		node_id = *session.Options.ImageName
		nodeType = scan.ImageScan
		log.Infof("Scanning image %s for secrets...", *session.Options.ImageName)
		result = &output.JSONImageSecretsOutput{
			ImageName: *session.Options.ImageName,
			Secrets:   []output.SecretFound{},
		}
	} else if len(*session.Options.Local) > 0 { // Scan local directory for secrets
		node_id = *session.Options.Local
		nodeType = scan.DirScan
		result = &output.JSONDirSecretsOutput{
			DirName: *session.Options.Local,
			Secrets: []output.SecretFound{},
		}
	} else if len(*session.Options.ContainerID) > 0 { // Scan existing container for secrets
		node_type = "container_image"
		node_id = *session.Options.ContainerID
		nodeType = scan.ContainerScan
		result = &output.JSONImageSecretsOutput{
			ContainerID: *session.Options.ContainerID,
			Secrets:     []output.SecretFound{},
		}
	}

	scanCtx := tasks.ScanContext{
		Context: ctx,
		IsAlive: atomic.Bool{},
	}

	scan.Scan(&scanCtx, nodeType, filters, "", node_id, "", func(sf output.SecretFound, s string) {
		result.AddSecret(sf)
	})

	if result == nil {
		log.Error("set either -local or -image-name flag")
		return
	}

	if len(*core.GetSession().Options.ConsoleURL) != 0 && len(*core.GetSession().Options.DeepfenceKey) != 0 {
		pub, err := output.NewPublisher(
			*core.GetSession().Options.ConsoleURL,
			strconv.Itoa(*core.GetSession().Options.ConsolePort),
			*core.GetSession().Options.DeepfenceKey,
		)
		if err != nil {
			log.Error(err.Error())
		}

		pub.SendReport(output.GetHostname(), *session.Options.ImageName, *session.Options.ContainerID, node_type)
		scanId := pub.StartScan(node_id, node_type)
		if len(scanId) == 0 {
			scanId = fmt.Sprintf("%s-%d", node_id, time.Now().UnixMilli())
		}
		pub.IngestSecretScanResults(scanId, result.GetSecrets())
		log.Info("scan id %s", scanId)
	}

	counts := output.CountBySeverity(result.GetSecrets())
	log.Infof("result severity counts: %+v", counts)

	if format == core.JSONOutput {
		err = result.WriteJSON()
		if err != nil {
			log.Fatal("main: error while writing secrets: %s", err)
		}
	} else {
		fmt.Println("summary:")
		fmt.Printf("  total=%d high=%d medium=%d low=%d\n", counts.Total, counts.High, counts.Medium, counts.Low)
		err = result.WriteTable()
		if err != nil {
			log.Fatal("main: error while writing secrets: %s", err)
		}
	}

	output.FailOn(
		counts,
		*core.GetSession().Options.FailOnHighCount,
		*core.GetSession().Options.FailOnMediumCount,
		*core.GetSession().Options.FailOnLowCount,
		*core.GetSession().Options.FailOnCount,
	)
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
