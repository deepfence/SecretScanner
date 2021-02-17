package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/deepfence/SecretScanner/core"
	"github.com/deepfence/SecretScanner/output"
	"github.com/deepfence/SecretScanner/signature"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
)

// Data type to store details about the container image after parsing manifest
type manifestItem struct {
	Config   string
	RepoTags []string
	Layers   []string
	LayerIds []string `json:",omitempty"`
}

var (
	imageTarFileName       = "save-output.tar"
	extractedImageFilesDir = "extracted-files"
)

type ImageScan struct {
	imageName     string
	imageId       string
	outputDir     string
	imageManifest manifestItem
}

// Function to retrieve contents of container images layer by layer
// @parameters
// imageScan - Structure with details of the container image to scan
// @returns
// Error - Errors, if any. Otherwise, returns nil
func (imageScan *ImageScan) extractImage() (error) {
	imageName := imageScan.imageName
	outputDir := imageScan.outputDir

	err := imageScan.saveImageData()
	if err != nil {
		core.GetSession().Log.Error("scanImage: Could save container image %s", err)
		return err
	}

	_, err = extractTarFile(imageName, path.Join(outputDir, imageTarFileName), outputDir)
	if err != nil {
		core.GetSession().Log.Error("scanImage: Could not extract image tar file %s", err)
		return err
	}

	imageManifest, err := extractDetailsFromManifest(outputDir)
	if err != nil {
		core.GetSession().Log.Error("ProcessImageLayers: Could not get image's history: %s," +
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
	outputDir := imageScan.outputDir
	// defer deleteTmpDir(outputDir)

	tempSecretsFound, err := imageScan.processImageLayers(outputDir, path.Join(outputDir, extractedImageFilesDir))
	if err != nil {
		core.GetSession().Log.Error("scanImage: %s", err)
		return tempSecretsFound, err
	}

	return tempSecretsFound, nil
}

// Scans a given directory recursively to find all secrets inside any file in the dir
// @parameters
// layer - layer ID, if we are scanning directory inside container image
// baseDir - Parent directory
// fullDir - Complete path of the directory to be scanned
// isFirstSecret - indicates if some secrets are already printed, used to properly format json
// @returns
// []output.SecretFound - List of all secrets found
// Error - Errors if any. Otherwise, returns nil
func scanSecretsInDir(layer string, baseDir string, fullDir string, isFirstSecret *bool) ([]output.SecretFound, error) {
	var tempSecretsFound []output.SecretFound

	if layer != "" {
		core.UpdateDirsPermissionsRW(fullDir)
	}

	for _, file := range core.GetMatchingFiles(fullDir) {
		//fmt.Println("filename: ", file.Path)

		relPath, err := filepath.Rel(path.Join(baseDir, layer), file.Path)
		if err != nil {
			core.GetSession().Log.Warn("scanSecretsInDir: Couldn't remove prefix of path: %s %s %s",
												baseDir, layer, file.Path)
			relPath = file.Path
		}

		// No need to scan sym links. This avoids hangs when scanning stderr, stdour or special file descriptors
		// Also, the pointed files will anyway be scanned directly
		if isSymLink(file.Path) {
			continue
		}

		// Add RW permissions for reading and deleting contents of containers, not for regular file system
		if layer != "" {
			err := os.Chmod(file.Path, 0600)
			if err != nil {
				core.GetSession().Log.Error("scanSecretsInDir changine file permission: %s", err)
			}
		}		
						
		contents, err := ioutil.ReadFile(file.Path)
		if err != nil {
			core.GetSession().Log.Error("scanSecretsInDir reading file: %s", err)
			// return tempSecretsFound, err
		} else {
			// fmt.Println(relPath, file.Filename, file.Extension, layer)
			secrets, err := signature.MatchPatternSignatures(contents, relPath, file.Filename, file.Extension, layer)
			if err != nil {
				core.GetSession().Log.Info("relPath: %s, Filename: %s, Extension: %s, layer: %s",
										relPath, file.Filename, file.Extension, layer)
				core.GetSession().Log.Error("scanSecretsInDir: %s", err)
				// return tempSecretsFound, err
			}
			output.PrintColoredSecrets(secrets, isFirstSecret)
			tempSecretsFound = append(tempSecretsFound, secrets...)
		}

		secrets := signature.MatchSimpleSignatures(relPath, file.Filename, file.Extension, layer)
		output.PrintColoredSecrets(secrets, isFirstSecret)
		tempSecretsFound = append(tempSecretsFound, secrets...)
		// Reset the matched Rule IDs to enable matched signatures for next file
		signature.ClearMatchedRuleSet()
	}

	return tempSecretsFound, nil
}

// Extract all the layers of the container image and then find secrets in each layer one by one
// @parameters
// imageScan - Structure with details of the container image to scan
// imageManifestPath - Complete path of directory where manifest of image has been extracted
// extractPath - Base directory where all the layers should be extracted to
// @returns
// []output.SecretFound - List of all secrets found
// Error - Errors if any. Otherwise, returns nil
func (imageScan *ImageScan) processImageLayers(imageManifestPath string, extractPath string) ([]output.SecretFound, error) {
	var tempSecretsFound []output.SecretFound
	var err error

	var isFirstSecret bool = true
	layerIDs := imageScan.imageManifest.LayerIds
	layerPaths := imageScan.imageManifest.Layers

	loopCntr := len(layerPaths)
	for i := 0; i < loopCntr; i++ {
		core.GetSession().Log.Debug("Analyzing layer path: %s", layerPaths[i])
		core.GetSession().Log.Debug("Analyzing layer: %s", layerIDs[i])
		// savelayerID = layerIDs[i]
		completeLayerPath := path.Join(imageManifestPath, layerPaths[i])
		targetDir := path.Join(extractPath, layerIDs[i])
		core.GetSession().Log.Info("Complete layer path: %s", completeLayerPath)
		core.GetSession().Log.Info("Extracted to directory: %s", targetDir)
		err = createRecursiveDir(targetDir)
		if err != nil {
			core.GetSession().Log.Error("ProcessImageLayers: Unable to create target directory" +
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
		secrets, err := scanSecretsInDir(layerIDs[i], extractPath, targetDir, &isFirstSecret)
		tempSecretsFound = append(tempSecretsFound, secrets...)
		if err != nil {
			core.GetSession().Log.Error("ProcessImageLayers: %s", err)
			// return tempSecretsFound, err
		}
	}

	return tempSecretsFound, nil
}

// Save container image as tar file in specified directory
// @parameters 
// imageScan - Structure with details of the container image to scan
// @returns
// Error - Errors if any. Otherwise, returns nil
func (imageScan *ImageScan) saveImageData() error {
	imageName := imageScan.imageName
	outputParam := path.Join(imageScan.outputDir, imageTarFileName)
	_, stdErr, retVal := runCommand("docker", "save", imageName, "-o", outputParam)
	if retVal != 0 {
		// fmt.Println(stdErr)
		return errors.New(stdErr)
	}

	core.GetSession().Log.Info("Image %s saved in %s", imageName, imageScan.outputDir)
	return nil
}

// Delete all the files and dirs recursively in specified directory
// @parameters 
// path - Directory whose contents need to be deleted
// wildcard - patterns to match the filenames (e.g. '*')
func deleteFiles(path string, wildCard string) {

	var val string
	files, _ := filepath.Glob(path + wildCard)
	for _, val = range files {
		os.RemoveAll(val)
	}
}

// Delete the temporary directory
// @parameters 
// outputDir - Directory which need to be deleted
func deleteTmpDir(outputDir string) {
	core.GetSession().Log.Info("Deleting temporary dir %s", outputDir)
	// Output dir will be empty string in case of error, don't delete
	if outputDir != "" {
		deleteFiles(outputDir+"/", "*")
		os.Remove(outputDir)
	}
}

// Create directory structure recursively, if they do not exist
// @parameters 
// completePath - Complete path of directory which needs to be created
// @returns
// Error - Errors if any. Otherwise, returns nil
func createRecursiveDir(completePath string) error {
	_, err := os.Stat(completePath)
	if os.IsNotExist(err) {
		core.GetSession().Log.Debug("Folder does not exist. Creating folder... %s", completePath)
		err = os.MkdirAll(completePath, os.ModePerm)
		if err != nil {
			core.GetSession().Log.Error("MkdirAll %q: %s", completePath, err)
		}
	}

	return err
}

// Create a sanitized string from image name which can used as a filename
// @parameters 
// imageName - Name of the container image
// @returns
// string - Sanitized string which can used as part of filename
func getSanitizedString(imageName string) string {
	reg, err := regexp.Compile("[^A-Za-z0-9]+")
	if err != nil {
		return "error"
	}
	sanitizedName := reg.ReplaceAllString(imageName, "")
	return sanitizedName
}


// Create a temporrary directory to extract the conetents of container image
// @parameters 
// imageName - Name of the container image
// @returns
// String - Complete path of the based directory where image will be extracted, empty string if error
// Error - Errors if any. Otherwise, returns nil
func getTmpDir(imageName string) (string, error) {

	var scanId string = "df_" + getSanitizedString(imageName)

	tempPath := filepath.Join(os.TempDir(), core.TempDirName, scanId) 
	
	if runtime.GOOS == "windows" {
		tempPath = "C:/ProgramData/Deepfence/temp/find_secrets/df_" + scanId
	}

	completeTempPath := path.Join(tempPath, extractedImageFilesDir)

	err := createRecursiveDir(completeTempPath)

	if err != nil {
		core.GetSession().Log.Error("getTmpDir: Could not create temp dir%s", err)
		return "", err
	}

	return tempPath, err
}

// Check if input is a symLink, not normal file/dir
// @returns
// bool - Return true if input is a symLink
func isSymLink(path string) bool {
	// can handle symbolic link, but will no follow the link
	fileInfo, err := os.Lstat(path)

	if err != nil {
		// panic(err)
		return false
	}

	// --- check if file is a symlink
	if fileInfo.Mode()&os.ModeSymlink == os.ModeSymlink {
		// fmt.Println("File is a symbolic link")
		return true
	}

	return false
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
	_, stdErr, retVal := runCommand("tar", "-xf", imageTarPath, "--warning=none", "-C"+path)
	if retVal != 0 {
		// fmt.Println(stdErr)
		return "", errors.New(stdErr)
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
