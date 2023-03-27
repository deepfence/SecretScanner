package scan

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/deepfence/SecretScanner/core"
	"github.com/deepfence/SecretScanner/output"
	"github.com/deepfence/SecretScanner/signature"
	"github.com/deepfence/vessel"
	"github.com/opencontainers/selinux/pkg/pwalkdir"
)

// Data type to store details about the container image after parsing manifest
type manifestItem struct {
	Config   string
	RepoTags []string
	Layers   []string
	LayerIds []string `json:",omitempty"`
}

var (
	imageTarFileName   = "save-output.tar"
	maxSecretsExceeded = errors.New("number of secrets exceeded max-secrets")
)

const (
	secret_pipeline_size = 100
)

type ImageScan struct {
	imageName     string
	imageId       string
	tempDir       string
	imageManifest manifestItem
	numSecrets    uint
}

// Function to retrieve contents of container images layer by layer
// @parameters
// imageScan - Structure with details of the container image to scan
// @returns
// Error - Errors, if any. Otherwise, returns nil
func (imageScan *ImageScan) extractImage(saveImage bool) error {
	imageName := imageScan.imageName
	tempDir := imageScan.tempDir
	imageScan.numSecrets = 0

	if saveImage {
		err := imageScan.saveImageData()
		if err != nil {
			core.GetSession().Log.Error("scanImage: Could not save container image: %s. Check if the image name is correct.", err)
			return err
		}
	}

	_, err := extractTarFile(imageName, path.Join(tempDir, imageTarFileName), tempDir)
	if err != nil {
		core.GetSession().Log.Error("scanImage: Could not extract image tar file: %s", err)
		return err
	}

	imageManifest, err := extractDetailsFromManifest(tempDir)
	if err != nil {
		core.GetSession().Log.Error("ProcessImageLayers: Could not get image's history: %s,"+
			" please specify repo:tag and check disk space \n", err.Error())
		return err
	}

	imageScan.imageManifest = imageManifest
	// reading image id from imanifest file json path and tripping off extension
	imageScan.imageId = strings.TrimSuffix(imageScan.imageManifest.Config, ".json")

	return nil
}

// Function to scan extracted layers of container images for secrets file by file
// @parameters
// imageScan - Structure with details of the container image to scan
// @returns
// []output.SecretFound - List of all secrets found
// Error - Errors, if any. Otherwise, returns nil
func (imageScan *ImageScan) scan() ([]output.SecretFound, error) {
	tempDir := imageScan.tempDir
	defer core.DeleteTmpDir(tempDir)

	tempSecretsFound, err := imageScan.processImageLayers(tempDir)
	if err != nil {
		core.GetSession().Log.Error("scanImage: %s", err)
		return tempSecretsFound, err
	}

	return tempSecretsFound, nil
}

// Function to scan extracted layers of container images for secrets file by file
// @parameters
// imageScan - Structure with details of the container image to scan
// @returns
// []output.SecretFound - List of all secrets found
// Error - Errors, if any. Otherwise, returns nil
func (imageScan *ImageScan) scanStream() (chan output.SecretFound, error) {
	return imageScan.processImageLayersStream(imageScan.tempDir)
}

func readFile(path string) ([]byte, error) {
	var content string
	file, err := os.OpenFile(path, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
		content += scanner.Text() + "\n"
	}
	return []byte(content), nil
}

func scanFile(filePath, relPath, fileName, fileExtension, layer string, numSecrets *uint, matchedRuleSet map[uint]uint) ([]output.SecretFound, error) {
	contents, err := readFile(filePath)
	if err != nil {
		return nil, err
	}
	// fmt.Println(relPath, file.Filename, file.Extension, layer)
	secrets, err := signature.MatchPatternSignatures(contents, relPath, fileName, fileExtension, layer, numSecrets, matchedRuleSet)
	if err != nil {
		return nil, err
	}
	return secrets, nil
}

// ScanSecretsInDir Scans a given directory recursively to find all secrets inside any file in the dir
// @parameters
// layer - layer ID, if we are scanning directory inside container image
// baseDir - Parent directory
// fullDir - Complete path of the directory to be scanned
// isFirstSecret - indicates if some secrets are already printed, used to properly format json
// @returns
// []output.SecretFound - List of all secrets found
// Error - Errors if any. Otherwise, returns nil
func ScanSecretsInDir(layer string, baseDir string, fullDir string, isFirstSecret *bool,
	numSecrets *uint, matchedRuleSet map[uint]uint) ([]output.SecretFound, error) {
	var tempSecretsFound []output.SecretFound
	if matchedRuleSet == nil {
		matchedRuleSet = make(map[uint]uint)
	}

	session := core.GetSession()

	if layer != "" {
		core.UpdateDirsPermissionsRW(fullDir)
	}

	maxFileSize := *session.Options.MaximumFileSize * 1024
	var file core.MatchFile
	var relPath string

	walkErr := pwalkdir.WalkN(fullDir, func(path string, f os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		var scanDirPath string
		if layer != "" {
			scanDirPath = strings.TrimPrefix(path, baseDir+"/"+layer)
			if scanDirPath == "" {
				scanDirPath = "/"
			}
		} else {
			scanDirPath = path
		}

		if f.IsDir() {
			if core.IsSkippableDir(scanDirPath, baseDir) {
				return filepath.SkipDir
			}
			return nil
		}

		// No need to scan sym links. This avoids hangs when scanning stderr, stdour or special file descriptors
		// Also, the pointed files will anyway be scanned directly
		if !f.Type().IsRegular() {
			return nil
		}

		finfo, err := f.Info()
		if err != nil {
			session.Log.Warn("Skipping %v as info could not be retrieved: %v", path, err)
			return nil
		}

		if uint(finfo.Size()) > maxFileSize || core.IsSkippableFileExtension(path) {
			return nil
		}

		file = core.NewMatchFile(path)

		relPath, err = filepath.Rel(filepath.Join(baseDir, layer), file.Path)
		if err != nil {
			session.Log.Warn("scanSecretsInDir: Couldn't remove prefix of path: %s %s %s",
				baseDir, layer, file.Path)
			relPath = file.Path
		}

		// Add RW permissions for reading and deleting contents of containers, not for regular file system
		if layer != "" {
			err = os.Chmod(file.Path, 0600)
			if err != nil {
				session.Log.Error("scanSecretsInDir changine file permission: %s", err)
			}
		}

		secrets, err := scanFile(file.Path, relPath, file.Filename, file.Extension, layer, numSecrets, matchedRuleSet)
		if err != nil {
			session.Log.Info("relPath: %s, Filename: %s, Extension: %s, layer: %s", relPath, file.Filename, file.Extension, layer)
			session.Log.Error("scanSecretsInDir: %s", err)
		} else {
			if len(secrets) > 0 {
				if *session.Options.Quiet {
					output.PrintColoredSecrets(secrets, isFirstSecret)
				}
				tempSecretsFound = append(tempSecretsFound, secrets...)
			}
		}

		secrets = signature.MatchSimpleSignatures(relPath, file.Filename, file.Extension, layer, numSecrets)
		if *session.Options.Quiet {
			output.PrintColoredSecrets(secrets, isFirstSecret)
		}
		tempSecretsFound = append(tempSecretsFound, secrets...)

		// Don't report secrets if number of secrets exceeds MAX value
		if *numSecrets >= *session.Options.MaxSecrets {
			return maxSecretsExceeded
		}
		return nil
	}, *session.Options.WorkersPerScan)

	if walkErr != nil {
		if walkErr == maxSecretsExceeded {
			session.Log.Warn("filepath.Walk: %s", walkErr)
			fmt.Printf("filepath.Walk: %s\n", walkErr)
		} else {
			session.Log.Error("Error in filepath.Walk: %s", walkErr)
			fmt.Printf("Error in filepath.Walk: %s\n", walkErr)
		}
	}

	return tempSecretsFound, nil
}

// ScanSecretsInDirStream Scans a given directory recursively to find all secrets inside any file in the dir
// @parameters
// layer - layer ID, if we are scanning directory inside container image
// baseDir - Parent directory
// fullDir - Complete path of the directory to be scanned
// isFirstSecret - indicates if some secrets are already printed, used to properly format json
// @returns
// chan output.SecretFound - Channel of all secrets found
// Error - Errors if any. Otherwise, returns nil
func ScanSecretsInDirStream(layer string, baseDir string, fullDir string, isFirstSecret *bool,
	numSecrets *uint, matchedRuleSet map[uint]uint) (chan output.SecretFound, error) {

	res := make(chan output.SecretFound, secret_pipeline_size)

	if matchedRuleSet == nil {
		matchedRuleSet = map[uint]uint{}
	}

	if layer != "" {
		core.UpdateDirsPermissionsRW(fullDir)
	}

	go func() {

		defer close(res)
		session := core.GetSession()
		maxFileSize := *session.Options.MaximumFileSize * 1024
		var file core.MatchFile
		var relPath string

		walkErr := pwalkdir.WalkN(fullDir, func(path string, f os.DirEntry, err error) error {
			if err != nil {
				return err
			}

			var scanDirPath string
			if layer != "" {
				scanDirPath = strings.TrimPrefix(path, baseDir+"/"+layer)
				if scanDirPath == "" {
					scanDirPath = "/"
				}
			} else {
				scanDirPath = path
			}

			if f.IsDir() {
				if core.IsSkippableDir(scanDirPath, baseDir) {
					return filepath.SkipDir
				}
				return nil
			}

			// No need to scan sym links. This avoids hangs when scanning stderr, stdour or special file descriptors
			// Also, the pointed files will anyway be scanned directly
			if !f.Type().IsRegular() {
				return nil
			}

			finfo, err := f.Info()
			if err != nil {
				session.Log.Warn("Skipping %v as info could not be retrieved: %v", path, err)
				return nil
			}

			if uint(finfo.Size()) > maxFileSize || core.IsSkippableFileExtension(path) {
				return nil
			}

			file = core.NewMatchFile(path)

			relPath, err = filepath.Rel(filepath.Join(baseDir, layer), file.Path)
			if err != nil {
				session.Log.Warn("scanSecretsInDir: Couldn't remove prefix of path: %s %s %s",
					baseDir, layer, file.Path)
				relPath = file.Path
			}

			// Add RW permissions for reading and deleting contents of containers, not for regular file system
			if layer != "" {
				err = os.Chmod(file.Path, 0600)
				if err != nil {
					session.Log.Error("scanSecretsInDir changine file permission: %s", err)
				}
			}

			secrets, err := scanFile(file.Path, relPath, file.Filename, file.Extension, layer, numSecrets, matchedRuleSet)
			if err != nil {
				session.Log.Info("relPath: %s, Filename: %s, Extension: %s, layer: %s", relPath, file.Filename, file.Extension, layer)
				session.Log.Error("scanSecretsInDir: %s", err)
			} else {
				if len(secrets) > 0 {
					if *session.Options.Quiet {
						output.PrintColoredSecrets(secrets, isFirstSecret)
					}
					for i := range secrets {
						res <- secrets[i]
					}
				}
			}

			secrets = signature.MatchSimpleSignatures(relPath, file.Filename, file.Extension, layer, numSecrets)
			if *session.Options.Quiet {
				output.PrintColoredSecrets(secrets, isFirstSecret)
			}
			for i := range secrets {
				res <- secrets[i]
			}
			// Don't report secrets if number of secrets exceeds MAX value
			if *numSecrets >= *session.Options.MaxSecrets {
				return maxSecretsExceeded
			}
			return nil
		}, *session.Options.WorkersPerScan)
		if walkErr != nil {
			if walkErr == maxSecretsExceeded {
				session.Log.Warn("filepath.Walk: %s", walkErr)
				fmt.Printf("filepath.Walk: %s\n", walkErr)
			} else {
				session.Log.Error("Error in filepath.Walk: %s", walkErr)
				fmt.Printf("Error in filepath.Walk: %s\n", walkErr)
			}
		}
	}()
	return res, nil
}

// Extract all the layers of the container image and then find secrets in each layer one by one
// @parameters
// imageScan - Structure with details of the container image to scan
// imageManifestPath - Complete path of directory where manifest of image has been extracted
// @returns
// []output.SecretFound - List of all secrets found
// Error - Errors if any. Otherwise, returns nil
func (imageScan *ImageScan) processImageLayers(imageManifestPath string) ([]output.SecretFound, error) {
	var tempSecretsFound []output.SecretFound
	var err error
	var isFirstSecret bool = true

	// extractPath - Base directory where all the layers should be extracted to
	extractPath := path.Join(imageManifestPath, core.ExtractedImageFilesDir)
	layerIDs := imageScan.imageManifest.LayerIds
	layerPaths := imageScan.imageManifest.Layers
	matchedRuleSet := make(map[uint]uint)

	loopCntr := len(layerPaths)
	var secrets []output.SecretFound
	for i := 0; i < loopCntr; i++ {
		core.GetSession().Log.Debug("Analyzing layer path: %s", layerPaths[i])
		core.GetSession().Log.Debug("Analyzing layer: %s", layerIDs[i])
		// savelayerID = layerIDs[i]
		completeLayerPath := path.Join(imageManifestPath, layerPaths[i])
		targetDir := path.Join(extractPath, layerIDs[i])
		core.GetSession().Log.Info("Complete layer path: %s", completeLayerPath)
		core.GetSession().Log.Info("Extracted to directory: %s", targetDir)
		err = core.CreateRecursiveDir(targetDir)
		if err != nil {
			core.GetSession().Log.Error("ProcessImageLayers: Unable to create target directory"+
				" to extract image layers... %s", err)
			return tempSecretsFound, err
		}

		_, error := extractTarFile("", completeLayerPath, targetDir)
		if error != nil {
			core.GetSession().Log.Error("ProcessImageLayers: Unable to extract image layer. Reason = %s", error.Error())
			// Don't stop. Print error and continue with remaning extracted files and other layers
			// return tempSecretsFound, error
		}
		core.GetSession().Log.Debug("Analyzing dir: %s", targetDir)
		secrets, err = ScanSecretsInDir(layerIDs[i], extractPath, targetDir, &isFirstSecret, &imageScan.numSecrets, matchedRuleSet)
		tempSecretsFound = append(tempSecretsFound, secrets...)
		if err != nil {
			core.GetSession().Log.Error("ProcessImageLayers: %s", err)
			// return tempSecretsFound, err
		}

		// Don't report secrets if number of secrets exceeds MAX value
		if imageScan.numSecrets >= *core.GetSession().Options.MaxSecrets {
			return tempSecretsFound, nil
		}
	}

	return tempSecretsFound, nil
}

// Extract all the layers of the container image and then stream secrets in each layer one by one
// @parameters
// imageScan - Structure with details of the container image to scan
// imageManifestPath - Complete path of directory where manifest of image has been extracted
// @returns
// []output.SecretFound - List of all secrets found
// Error - Errors if any. Otherwise, returns nil
func (imageScan *ImageScan) processImageLayersStream(imageManifestPath string) (chan output.SecretFound, error) {
	res := make(chan output.SecretFound, secret_pipeline_size)

	go func() {
		var err error
		var isFirstSecret bool = true

		defer close(res)

		// extractPath - Base directory where all the layers should be extracted to
		extractPath := path.Join(imageManifestPath, core.ExtractedImageFilesDir)
		layerIDs := imageScan.imageManifest.LayerIds
		layerPaths := imageScan.imageManifest.Layers
		matchedRuleSet := make(map[uint]uint)

		loopCntr := len(layerPaths)
		var secrets []output.SecretFound
		for i := 0; i < loopCntr; i++ {
			core.GetSession().Log.Debug("Analyzing layer path: %s", layerPaths[i])
			core.GetSession().Log.Debug("Analyzing layer: %s", layerIDs[i])
			// savelayerID = layerIDs[i]
			completeLayerPath := path.Join(imageManifestPath, layerPaths[i])
			targetDir := path.Join(extractPath, layerIDs[i])
			core.GetSession().Log.Info("Complete layer path: %s", completeLayerPath)
			core.GetSession().Log.Info("Extracted to directory: %s", targetDir)
			err = core.CreateRecursiveDir(targetDir)
			if err != nil {
				core.GetSession().Log.Error("ProcessImageLayers: Unable to create target directory"+
					" to extract image layers... %v", err)
				continue
			}

			_, error := extractTarFile("", completeLayerPath, targetDir)
			if error != nil {
				core.GetSession().Log.Error("ProcessImageLayers: Unable to extract image layer. Reason = %s", error.Error())
				// Don't stop. Print error and continue with remaning extracted files and other layers
				continue
			}
			core.GetSession().Log.Debug("Analyzing dir: %s", targetDir)
			secrets, err = ScanSecretsInDir(layerIDs[i], extractPath, targetDir, &isFirstSecret, &imageScan.numSecrets, matchedRuleSet)
			for i := range secrets {
				res <- secrets[i]
			}
			if err != nil {
				core.GetSession().Log.Error("ProcessImageLayers: %s", err)
				continue
			}

			// Don't report secrets if number of secrets exceeds MAX value
			if imageScan.numSecrets >= *core.GetSession().Options.MaxSecrets {
				break
			}
		}
	}()

	return res, nil
}

// Save container image as tar file in specified directory
// @parameters
// imageScan - Structure with details of the container image to scan
// @returns
// Error - Errors if any. Otherwise, returns nil
func (imageScan *ImageScan) saveImageData() error {
	imageName := imageScan.imageName
	outputParam := path.Join(imageScan.tempDir, imageTarFileName)
	drun, err := vessel.NewRuntime()
	if err != nil {
		return err
	}
	fmt.Printf("Scanning image %s for secrets...\n", outputParam)
	_, err = drun.Save(imageName, outputParam)

	if err != nil {
		return err
	}
	core.GetSession().Log.Info("Image %s saved in %s", imageName, imageScan.tempDir)
	return nil
}

// Extract the contents of container image and save it in specified dir
// @parameters
// imageName - Name of the container image to save
// imageTarPath - Complete path where tarball of the image is stored
// extractPath - Complete path of directory where contents of image are to be extracted
// @returns
// string - directory where contents of image are extracted
// Error - Errors, if any. Otherwise, returns nil
func extractTarFile(imageName, imageTarPath string, extractPath string) (string, error) {
	core.GetSession().Log.Debug("Started extracting tar file %s", imageTarPath)

	path := extractPath

	// Extract the contents of image from tar file
	if err := untar(imageTarPath, path); err != nil {
		fmt.Println(err)
		return "", err
	}

	core.GetSession().Log.Debug("Finished extracting tar file %s", imageTarPath)
	return path, nil
}

// Extract all the details from image manifest
// @parameters
// path - Complete path where image contents are extracted
// @returns
// manifestItem - The manifestItem containing details about image layers
// Error - Errors, if any. Otherwise, returns nil
func untar(tarName string, xpath string) (err error) {
	tarFile, err := os.Open(tarName)
	if err != nil {
		return err
	}
	defer func() {
		err = tarFile.Close()
	}()

	absPath, err := filepath.Abs(xpath)
	if err != nil {
		return err
	}

	tr := tar.NewReader(tarFile)
	if strings.HasSuffix(tarName, ".gz") || strings.HasSuffix(tarName, ".gzip") {
		gz, err := gzip.NewReader(tarFile)
		if err != nil {
			return err
		}
		defer gz.Close()
		tr = tar.NewReader(gz)
	}

	// untar each segment
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// determine proper file path info
		finfo := hdr.FileInfo()
		fileName := hdr.Name
		if filepath.IsAbs(fileName) {
			fileName, err = filepath.Rel("/", fileName)
			if err != nil {
				return err
			}
		}

		absFileName := filepath.Join(absPath, fileName)
		if strings.Contains(fileName, "/") {
			relPath := strings.Split(fileName, "/")
			var absDirPath string
			if len(relPath) > 1 {
				dirs := relPath[0 : len(relPath)-1]
				absDirPath = filepath.Join(absPath, strings.Join(dirs, "/"))
			}
			if err := os.MkdirAll(absDirPath, 0755); err != nil {
				fmt.Println(err.Error())
			}
		}

		if finfo.Mode().IsDir() {
			if err := os.MkdirAll(absFileName, 0755); err != nil {
				return err
			}
			continue
		}

		// create new file with original file mode
		file, err := os.OpenFile(absFileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC, finfo.Mode().Perm())
		if err != nil {
			fmt.Println(err.Error())
			return err
		}
		// fmt.Printf("x %s\n", absFileName)
		n, cpErr := io.Copy(file, tr)
		if closeErr := file.Close(); closeErr != nil { // close file immediately
			fmt.Println("closeErr:" + closeErr.Error())
			return err
		}
		if cpErr != nil {
			fmt.Println("copyErr:" + cpErr.Error())
			return cpErr
		}
		if n != finfo.Size() {
			return fmt.Errorf("unexpected bytes written: wrote %d, want %d", n, finfo.Size())
		}
	}
	return nil
}

// Extract all the details from image manifest
// @parameters
// path - Complete path where image contents are extracted
// @returns
// manifestItem - The manifestItem containing details about image layers
// Error - Errors, if any. Otherwise, returns nil
func extractDetailsFromManifest(path string) (manifestItem, error) {
	mf, err := os.Open(path + "/manifest.json")
	if err != nil {
		return manifestItem{}, err
	}
	defer mf.Close()

	var manifest []manifestItem
	if err = json.NewDecoder(mf).Decode(&manifest); err != nil {
		return manifestItem{}, err
	} else if len(manifest) != 1 {
		return manifestItem{}, err
	}
	var layerIds []string
	for _, layer := range manifest[0].Layers {
		trimmedLayerId := strings.TrimSuffix(layer, "/layer.tar")
		// manifests saved by some versions of skopeo has .tar extentions
		trimmedLayerId = strings.TrimSuffix(trimmedLayerId, ".tar")
		layerIds = append(layerIds, trimmedLayerId)
	}
	manifest[0].LayerIds = layerIds
	// ImageScan.imageManifest = manifest[0]
	return manifest[0], nil
}

// Execute the specified command and return the output
// @parameters
// name - Command to be executed
// args - all the arguments to be passed to the command
// @returns
// string - contents of standard output
// string - contents of standard error
// int - exit code of the executed command
func runCommand(name string, args ...string) (stdout string, stderr string, exitCode int) {
	var defaultFailedCode = 1
	var outbuf, errbuf bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdout = &outbuf
	cmd.Stderr = &errbuf

	err := cmd.Run()
	stdout = outbuf.String()
	stderr = errbuf.String()

	if err != nil {
		// try to get the exit code
		if exitError, ok := err.(*exec.ExitError); ok {
			ws := exitError.Sys().(syscall.WaitStatus)
			exitCode = ws.ExitStatus()
		} else {
			// This will happen (in OSX) if `name` is not available in $PATH,
			// in this situation, exit code could not be get, and stderr will be
			// empty string very likely, so we use the default fail code, and format err
			// to string and set to stderr
			log.Printf("Could not get exit code for failed program: %v, %v", name, args)
			exitCode = defaultFailedCode
			if stderr == "" {
				stderr = err.Error()
			}
		}
	} else {
		// success, exitCode should be 0 if go is ok
		ws := cmd.ProcessState.Sys().(syscall.WaitStatus)
		exitCode = ws.ExitStatus()
	}
	return
}

type ImageExtractionResult struct {
	Secrets []output.SecretFound
	ImageId string
}

func ExtractAndScanImage(image string) (*ImageExtractionResult, error) {
	tempDir, err := core.GetTmpDir(image)
	if err != nil {
		return nil, err
	}
	// defer core.DeleteTmpDir(tempDir)

	imageScan := ImageScan{imageName: image, imageId: "", tempDir: tempDir}
	err = imageScan.extractImage(true)

	if err != nil {
		return nil, err
	}

	secrets, err := imageScan.scan()

	if err != nil {
		return nil, err
	}
	return &ImageExtractionResult{ImageId: imageScan.imageId, Secrets: secrets}, nil
}

func ExtractAndScanImageStream(image string) (chan output.SecretFound, error) {
	tempDir, err := core.GetTmpDir(image)
	if err != nil {
		return nil, err
	}

	imageScan := ImageScan{imageName: image, imageId: "", tempDir: tempDir}
	err = imageScan.extractImage(true)

	if err != nil {
		core.DeleteTmpDir(tempDir)
		return nil, err
	}

	stream, err := imageScan.scanStream()

	if err != nil {
		core.DeleteTmpDir(tempDir)
		return nil, err
	}

	res := make(chan output.SecretFound, secret_pipeline_size)

	go func() {
		defer core.DeleteTmpDir(tempDir)
		defer close(res)
		for i := range stream {
			res <- i
		}
	}()

	return res, nil

}

func ExtractAndScanFromTar(tarFolder string, imageName string) (*ImageExtractionResult, error) {
	// defer core.DeleteTmpDir(tarFolder)

	imageScan := ImageScan{imageName: imageName, imageId: "", tempDir: tarFolder}
	err := imageScan.extractImage(false)

	if err != nil {
		return nil, err
	}

	secrets, err := imageScan.scan()

	if err != nil {
		return nil, err
	}
	return &ImageExtractionResult{ImageId: imageScan.imageId, Secrets: secrets}, nil
}
