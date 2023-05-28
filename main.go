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

	"github.com/deepfence/SecretScanner/core"
	"github.com/deepfence/SecretScanner/output"
	"github.com/deepfence/SecretScanner/scan"
	"github.com/deepfence/SecretScanner/server"
	"github.com/deepfence/SecretScanner/signature"
	"github.com/fatih/color"
)

const (
	PLUGIN_NAME = "SecretScanner"
)

var (
	socketPath         = flag.String("socket-path", "", "The gRPC server unix socket path")
	httpPort           = flag.String("http-port", "", "When set the http server will come up at port with df es as output")
	standAloneHTTPPort = flag.String("standalone-http-port", "", "use to run secret scanner as a standalone service")
)

// Read the regex signatures from config file, options etc.
// and setup the session to start scanning for secrets
var session = core.GetSession()

// Scan a container image for secrets layer by layer
// @parameters
// image - Name of the container image to scan (e.g. "alpine:3.5")
// @returns
// Error, if any. Otherwise, returns nil
func findSecretsInImage(image string) (*output.JsonImageSecretsOutput, error) {

	res, err := scan.ExtractAndScanImage(image)
	if err != nil {
		return nil, err
	}
	jsonImageSecretsOutput := output.JsonImageSecretsOutput{ImageName: image}
	jsonImageSecretsOutput.SetTime()
	jsonImageSecretsOutput.SetImageId(res.ImageId)
	jsonImageSecretsOutput.PrintJsonHeader()
	jsonImageSecretsOutput.PrintJsonFooter()
	jsonImageSecretsOutput.SetSecrets(res.Secrets)

	return &jsonImageSecretsOutput, nil
}

// Scan a directory
// @parameters
// dir - Complete path of the directory to be scanned
// @returns
// Error, if any. Otherwise, returns nil
func findSecretsInDir(dir string) (*output.JsonDirSecretsOutput, error) {
	var isFirstSecret bool = true

	secrets, err := scan.ScanSecretsInDir("", "", dir, &isFirstSecret, nil)
	if err != nil {
		core.GetSession().Log.Error("findSecretsInDir: %s", err)
		return nil, err
	}

	jsonDirSecretsOutput := output.JsonDirSecretsOutput{DirName: *session.Options.Local}
	jsonDirSecretsOutput.SetTime()
	jsonDirSecretsOutput.PrintJsonHeader()
	jsonDirSecretsOutput.PrintJsonFooter()
	jsonDirSecretsOutput.SetSecrets(secrets)

	return &jsonDirSecretsOutput, nil
}

// Scan a container for secrets
// @parameters
// containerId - Id of the container to scan (e.g. "0fdasf989i0")
// @returns
// Error, if any. Otherwise, returns nil
func findSecretsInContainer(containerId string, containerNS string) (*output.JsonImageSecretsOutput, error) {

	res, err := scan.ExtractAndScanContainer(containerId, containerNS, nil)
	if err != nil {
		return nil, err
	}
	jsonImageSecretsOutput := output.JsonImageSecretsOutput{ContainerId: containerId}
	jsonImageSecretsOutput.SetTime()
	jsonImageSecretsOutput.SetImageId(res.ContainerId)
	jsonImageSecretsOutput.PrintJsonHeader()
	jsonImageSecretsOutput.PrintJsonFooter()
	jsonImageSecretsOutput.SetSecrets(res.Secrets)

	return &jsonImageSecretsOutput, nil
}

type SecretsWriter interface {
	WriteSecrets(jsonFilename string) error
}

func runOnce() {
	var output SecretsWriter
	var input string

	// Scan container image for secrets
	if len(*session.Options.ImageName) > 0 {
		fmt.Printf("Scanning image %s for secrets...\n", *session.Options.ImageName)
		jsonOutput, err := findSecretsInImage(*session.Options.ImageName)
		if err != nil {
			core.GetSession().Log.Fatal("main: error while scanning image: %s", err)
		}
		output = jsonOutput
	}

	// Scan local directory for secrets
	if len(*session.Options.Local) > 0 {
		fmt.Printf("[*] Scanning local directory: %s\n", color.BlueString(*session.Options.Local))
		jsonOutput, err := findSecretsInDir(*session.Options.Local)
		if err != nil {
			core.GetSession().Log.Fatal("main: error while scanning dir: %s", err)
		}
		output = jsonOutput
	}

	// Scan existing container for secrets
	if len(*session.Options.ContainerId) > 0 {
		fmt.Printf("Scanning container %s for secrets...\n", *session.Options.ContainerId)
		jsonOutput, err := findSecretsInContainer(*session.Options.ContainerId, *session.Options.ContainerNS)
		if err != nil {
			core.GetSession().Log.Fatal("main: error while scanning container: %s", err)
		}
		output = jsonOutput
	}

	if output == nil {
		core.GetSession().Log.Error("set either -local or -image-name flag")
		return
	}

	jsonFilename, err := core.GetJsonFilepath(input)
	if err != nil {
		core.GetSession().Log.Fatal("main: error while retrieving json output: %s", err)
	}
	err = output.WriteSecrets(jsonFilename)
	if err != nil {
		core.GetSession().Log.Fatal("main: error whilewriting secrets: %s", err)
	}
}

func main() {
	// Process and store the read signatures
	signature.ProcessSignatures(session.Config.Signatures)

	// Build Hyperscan database for fast scanning
	signature.BuildHsDb()

	flag.Parse()

	if *socketPath != "" {
		err := server.RunServer(*socketPath, PLUGIN_NAME)
		if err != nil {
			core.GetSession().Log.Fatal("main: failed to serve: %v", err)
		}
	} else if *httpPort != "" {
		err := server.RunHttpServer(*httpPort)
		if err != nil {
			core.GetSession().Log.Fatal("main: failed to serve through http: %v", err)
		}
	} else if *standAloneHTTPPort != "" {
		err := server.RunStandaloneHttpServer(*standAloneHTTPPort)
		if err != nil {
			core.GetSession().Log.Fatal("main: failed to serve through http: %v", err)
		}
	} else {
		runOnce()
	}
}
