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
	"archive/tar"
	"context"
	"encoding/json"
	"flag"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path"
	"path/filepath"
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
	"github.com/deepfence/YaraHunter/pkg/threatintel"

	pb "github.com/deepfence/agent-plugins-grpc/srcgo"
)

const (
	PLUGIN_NAME = "SecretScanner"
)

var (
	socketPath     = flag.String("socket-path", "", "The gRPC server unix socket path")
	version        string
	checksumFile   = "checksum.txt"
	sourceRuleFile = "df-secret.json"
	secretRuleFile = "secret.yar"
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

	log.Infof("version: %s", version)

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

	// update rules required for cli mode
	if *socketPath == "" {
		updateRules(ctx, core.GetSession().Options)
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

func updateRules(ctx context.Context, opts *core.Options) {
	log.Infof("check and update secret rules")

	listing, err := threatintel.FetchThreatIntelListing(ctx, version, *opts.Product, *opts.License)
	if err != nil {
		log.Fatal(err)
	}

	rulesInfo, err := listing.GetLatest(version, threatintel.SecretDBType)
	if err != nil {
		log.Fatal(err)
	}
	log.Debugf("rulesInfo: %+v", rulesInfo)

	// make sure output rules directory exists
	os.MkdirAll(*opts.RulesPath, fs.ModePerm)

	// check if update required
	if threatintel.SkipRulesUpdate(filepath.Join(*opts.RulesPath, checksumFile), rulesInfo.Checksum) {
		log.Info("skip rules update")
		return
	}

	log.Info("download new rules")
	content, err := threatintel.DownloadFile(ctx, rulesInfo.URL)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("rules file size: %d bytes", content.Len())

	// write new checksum
	if err := os.WriteFile(
		filepath.Join(*opts.RulesPath, checksumFile), []byte(rulesInfo.Checksum), fs.ModePerm); err != nil {
		log.Fatal(err)
	}

	// write rules file
	outRuleFile := filepath.Join(*opts.RulesPath, secretRuleFile)
	threatintel.ProcessTarGz(content.Bytes(), sourceRuleFile, outRuleFile, processSecretRules)
}

func processSecretRules(header *tar.Header, reader io.Reader, outPath string) error {

	var fb threatintel.FeedsBundle
	if err := json.NewDecoder(reader).Decode(&fb); err != nil {
		log.Error(err)
		return err
	}

	if err := threatintel.ExportYaraRules(outPath, fb.ScannerFeeds.SecretRules, fb.Extra); err != nil {
		log.Error(err)
		return err
	}

	return nil
}
