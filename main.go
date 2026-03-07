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
	"path/filepath"
	"strconv"

	"github.com/deepfence/SecretScanner/core"
	"github.com/deepfence/SecretScanner/jobs"
	"github.com/deepfence/SecretScanner/output"
	"github.com/deepfence/SecretScanner/server"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

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
	zerolog.CallerMarshalFunc = func(pc uintptr, file string, line int) string {
		return filepath.Base(file) + ":" + strconv.Itoa(line)
	}
	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "2006-01-02T15:04:05Z07:00"}).
		With().Timestamp().Caller().Logger()

	log.Info().Str("version", version).Msg("starting")

	flag.Parse()

	if *core.GetSession().Options.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt)

	out.ScanStatusFilename = jobs.GetDfInstallDir() + "/var/log/fenced/secret-scan-log/secret_scan_log.log"
	out.ScanFilename = jobs.GetDfInstallDir() + "/var/log/fenced/secret-scan/secret_scan.log"

	runnerOpts := runner.RunnerOptions{
		SocketPath:           *socketPath,
		RulesPath:            *core.GetSession().Options.RulesPath,
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

	// Download rules if updater is enabled and in CLI mode
	if *socketPath == "" && *core.GetSession().Options.EnableUpdater {
		downloadRules(ctx, core.GetSession().Options)
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

func downloadRules(ctx context.Context, opts *core.Options) {
	log.Info().Msg("downloading secret rules")

	// Check if rules already exist
	rulesFile := filepath.Join(*opts.RulesPath, secretRuleFile)
	if _, err := os.Stat(rulesFile); err == nil {
		log.Info().Str("file", rulesFile).Msg("rules file already exists, skipping download")
		return
	}

	// Make sure output rules directory exists
	os.MkdirAll(*opts.RulesPath, fs.ModePerm)

	// Download rules from versioned URL
	rulesURL := threatintel.SecretRulesURL(version)
	log.Info().Str("url", rulesURL).Msg("downloading rules")

	content, err := threatintel.DownloadFile(ctx, rulesURL)
	if err != nil {
		log.Error().Err(err).Msg("failed to download rules, continuing with bundled rules if available")
		return
	}

	log.Info().Int("bytes", content.Len()).Msg("rules file size")

	// Process and write rules file
	outRuleFile := filepath.Join(*opts.RulesPath, secretRuleFile)
	err = threatintel.ProcessTarGz(content.Bytes(), sourceRuleFile, outRuleFile, processSecretRules)
	if err != nil {
		log.Error().Err(err).Msg("failed to process rules")
	}
}

func processSecretRules(header *tar.Header, reader io.Reader, outPath string) error {
	var fb threatintel.FeedsBundle
	if err := json.NewDecoder(reader).Decode(&fb); err != nil {
		log.Error().Err(err).Msg("failed to decode feeds bundle")
		return err
	}

	if err := threatintel.ExportYaraRules(outPath, fb.ScannerFeeds.SecretRules, fb.Extra); err != nil {
		log.Error().Err(err).Msg("failed to export yara rules")
		return err
	}

	return nil
}
