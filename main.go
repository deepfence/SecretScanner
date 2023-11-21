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
	"flag"
	"fmt"
	"os"
	"path"
	"runtime"
	"strconv"
	"time"

	"github.com/deepfence/SecretScanner/core"
	"github.com/deepfence/SecretScanner/output"
	"github.com/deepfence/SecretScanner/scan"
	"github.com/deepfence/SecretScanner/server"
	"github.com/deepfence/SecretScanner/signature"
	log "github.com/sirupsen/logrus"
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

// Scan a container image for secrets layer by layer
// @parameters
// image - Name of the container image to scan (e.g. "alpine:3.5")
// @returns
// Error, if any. Otherwise, returns nil
func findSecretsInImage(image string) (*output.JSONImageSecretsOutput, error) {

	res, err := scan.ExtractAndScanImage(image)
	if err != nil {
		return nil, err
	}
	jsonImageSecretsOutput := output.JSONImageSecretsOutput{ImageName: image}
	jsonImageSecretsOutput.SetTime()
	jsonImageSecretsOutput.SetImageID(res.ImageId)
	jsonImageSecretsOutput.SetSecrets(res.Secrets)

	return &jsonImageSecretsOutput, nil
}

// Scan a directory
// @parameters
// dir - Complete path of the directory to be scanned
// @returns
// Error, if any. Otherwise, returns nil
func findSecretsInDir(dir string) (*output.JSONDirSecretsOutput, error) {
	var isFirstSecret bool = true

	secrets, err := scan.ScanSecretsInDir("", "", dir, &isFirstSecret, nil)
	if err != nil {
		log.Error("findSecretsInDir: %s", err)
		return nil, err
	}

	jsonDirSecretsOutput := output.JSONDirSecretsOutput{DirName: *session.Options.Local}
	jsonDirSecretsOutput.SetTime()
	jsonDirSecretsOutput.SetSecrets(secrets)

	return &jsonDirSecretsOutput, nil
}

// Scan a container for secrets
// @parameters
// containerId - Id of the container to scan (e.g. "0fdasf989i0")
// @returns
// Error, if any. Otherwise, returns nil
func findSecretsInContainer(containerId string, containerNS string) (*output.JSONImageSecretsOutput, error) {

	res, err := scan.ExtractAndScanContainer(containerId, containerNS, nil)
	if err != nil {
		return nil, err
	}
	jsonImageSecretsOutput := output.JSONImageSecretsOutput{ContainerID: containerId}
	jsonImageSecretsOutput.SetTime()
	jsonImageSecretsOutput.SetImageID(res.ContainerId)
	jsonImageSecretsOutput.SetSecrets(res.Secrets)

	return &jsonImageSecretsOutput, nil
}

type SecretsWriter interface {
	WriteJSON() error
	WriteTable() error
	GetSecrets() []output.SecretFound
}

func runOnce(format string) {
	var result SecretsWriter
	var err error
	node_type := ""
	node_id := ""

	// Scan container image for secrets
	if len(*session.Options.ImageName) > 0 {
		node_type = "image"
		node_id = *session.Options.ImageName
		log.Infof("Scanning image %s for secrets...", *session.Options.ImageName)
		result, err = findSecretsInImage(*session.Options.ImageName)
		if err != nil {
			log.Fatal("main: error while scanning image: %s", err)
		}
	}

	// Scan local directory for secrets
	if len(*session.Options.Local) > 0 {
		node_id = output.GetHostname()
		log.Debugf("Scanning local directory: %s", *session.Options.Local)
		result, err = findSecretsInDir(*session.Options.Local)
		if err != nil {
			log.Fatal("main: error while scanning dir: %s", err)
		}
	}

	// Scan existing container for secrets
	if len(*session.Options.ContainerID) > 0 {
		node_type = "container_image"
		node_id = *session.Options.ContainerID
		log.Debugf("Scanning container %s for secrets...", *session.Options.ContainerID)
		result, err = findSecretsInContainer(*session.Options.ContainerID, *session.Options.ContainerNS)
		if err != nil {
			log.Fatal("main: error while scanning container: %s", err)
		}
	}

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
	// Process and store the read signatures
	signature.ProcessSignatures(session.Config.Signatures)

	// Build Hyperscan database for fast scanning
	signature.BuildHsDb()

	flag.Parse()

	if *core.GetSession().Options.Debug {
		log.SetLevel(log.DebugLevel)
	}

	if *socketPath != "" {
		err := server.RunServer(*socketPath, PLUGIN_NAME)
		if err != nil {
			log.Fatal("main: failed to serve: %v", err)
		}
	} else {
		runOnce(*core.GetSession().Options.OutFormat)
	}
}
