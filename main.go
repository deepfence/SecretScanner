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
	"fmt"
	"github.com/deepfence/SecretScanner/core"
	"github.com/deepfence/SecretScanner/output"
	"github.com/deepfence/SecretScanner/signature"
	"github.com/fatih/color"
)

// Read the regex signatures from config file, options etc.
// and setup the session to start scanning for secrets
var session = core.GetSession()

// Scan a container image for secrets layer by layer
// @parameters
// image - Name of the container image to scan (e.g. "alpine:3.5")
// @returns
// Error, if any. Otherwise, returns nil
func findSecretsInImage(image string) error {
	// Save the image as tar
	err := scanImage(image)
	if err != nil {
		core.GetSession().Log.Fatal("findSecretsInImage: %s", err)
		return err
	}
	return nil
}

func main() {
	// Process and store the read signatures
	signature.ProcessSignatures(session.Config.Signatures)

	// Build Hyperscan database for fast scanning
	signature.BuildHsDb()

	// Scan container image for secrets
	if len(*session.Options.ImageName) > 0 {
		fmt.Printf("Scanning image %s for secrets...\n", *session.Options.ImageName)
		findSecretsInImage(*session.Options.ImageName)
	}

	// Scan local directory for secrets
	if len(*session.Options.Local) > 0 {
		fmt.Printf("[*] Scanning local directory: %s\n", color.BlueString(*session.Options.Local))

		secrets, err := scanSecretsInDir("", "", *session.Options.Local)
		if err != nil {
			core.GetSession().Log.Fatal("scanSecretsInDir: %s", err)			
		}

		jsonDirSecretsOutput := output.JsonDirSecretsOutput{DirName: *session.Options.Local, Secrets: secrets}
		jsonDirSecretsOutput.SetTime()
		jsonDirSecretsOutput.WriteSecrets(getSanitizedString(*session.Options.Local) + "-secrets.json")
	}
}
