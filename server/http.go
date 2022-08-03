package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"strconv"

	"github.com/Jeffail/tunny"
	"github.com/deepfence/SecretScanner/core"
	"github.com/deepfence/SecretScanner/output"
	"github.com/deepfence/SecretScanner/scan"
)

const (
	scanStatusComplete      = "COMPLETE"
	scanStatusError         = "ERROR"
	defaultScanConcurrency  = 5
	secretScanIndexName     = "secret-scan"
	secretScanLogsIndexName = "secret-scan-logs"
)

var (
	scanConcurrency    int
	httpScanWorkerPool *tunny.Pool
)

type imageParameters struct {
	imageName string
	scanId    string
	form      url.Values
}

func init() {
	var err error
	scanConcurrency, err = strconv.Atoi(os.Getenv("SECRET_SCAN_CONCURRENCY"))
	if err != nil {
		scanConcurrency = defaultScanConcurrency
	}
	httpScanWorkerPool = tunny.NewFunc(scanConcurrency, processImageWrapper)
}

func runSecretScan(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		fmt.Fprintf(writer, "ParseForm() err: %v", err)
		return
	} else if request.PostForm.Get("image_name_with_tag_list") == "" {
		http.Error(writer, "{\"error\":\"Image Name with tag list is required \"}", http.StatusConflict)
	} else {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		fmt.Fprintf(writer, "{\"status\": \"Scan Queued\"}")
		go processScans(request.PostForm)
	}
}

func processScans(form url.Values) {
	imageNameList := form["image_name_with_tag_list"]
	for index, imageName := range imageNameList {
		go httpScanWorkerPool.Process(imageParameters{imageName: imageName, scanId: form["scan_id_list"][index], form: form})
	}
}

func processImageWrapper(imageParamsInterface interface{}) interface{} {
	imageParams, ok := imageParamsInterface.(imageParameters)
	if !ok {
		fmt.Println("Error reading input from API")
		return nil
	}
	processImage(imageParams.imageName, imageParams.scanId, imageParams.form)
	return nil
}

func processImage(imageName string, scanId string, form url.Values) {
	tempFolder, err := core.GetTmpDir(imageName)
	if err != nil {
		fmt.Println("error creating temp dirs:" + err.Error())
		return
	}
	imageSaveCommand := exec.Command("python3", "/home/deepfence/usr/registry_image_save.py", "--image_name_with_tag", imageName, "--registry_type", form.Get("registry_type"),
		"--mgmt_console_url", output.MgmtConsoleUrl, "--deepfence_key", output.DeepfenceKey, "--credential_id", form.Get("credential_id"),
		"--output_folder", tempFolder)
	_, err = runCommand(imageSaveCommand, "Image Save:"+imageName)
	if err != nil {
		fmt.Println("error saving image:" + err.Error())
		return
	}
	scanAndPublish(imageName, scanId, tempFolder, form)
}

func scanAndPublish(imageName string, scanId string, tempDir string, postForm url.Values) {
	var secretScanLogDoc = make(map[string]interface{})
	secretScanLogDoc["scan_status"] = "IN_PROGRESS"
	secretScanLogDoc["node_id"] = imageName
	secretScanLogDoc["node_name"] = imageName
	secretScanLogDoc["time_stamp"] = core.GetTimestamp()
	secretScanLogDoc["@timestamp"] = core.GetCurrentTime()
	secretScanLogDoc["scan_id"] = scanId
	for key, value := range postForm {
		if len(value) > 0 {
			secretScanLogDoc[key] = value[0]
		}
	}
	secretScanLogDoc["image_name_with_tag_list"] = nil
	secretScanLogDoc["scan_id_list"] = nil
	byteJson, err := json.Marshal(secretScanLogDoc)
	if err != nil {
		fmt.Println("Error in marshalling secret in_progress log object to json:" + err.Error())
	} else {
		err = output.IngestSecretScanResults(string(byteJson), secretScanLogsIndexName)
		if err != nil {
			fmt.Println("Error in updating in_progress log" + err.Error())
		}
	}
	res, err := scan.ExtractAndScanFromTar(tempDir, imageName)
	if err != nil {
		secretScanLogDoc["scan_status"] = "ERROR"
		byteJson, err := json.Marshal(secretScanLogDoc)
		if err != nil {
			fmt.Println("Error in marshalling secret result object to json:" + err.Error())
			return
		}
		err = output.IngestSecretScanResults(string(byteJson), secretScanLogsIndexName)
		if err != nil {
			fmt.Println("error ingesting data: " + err.Error())
		}
		return
	}
	timestamp := core.GetTimestamp()
	currTime := core.GetCurrentTime()
	secrets := output.SecretsToSecretInfos(res.Secrets)
	for _, secret := range secrets {
		var secretScanDoc = make(map[string]interface{})
		for key, value := range postForm {
			if len(value) > 0 {
				secretScanDoc[key] = value[0]
			}
		}
		secretScanDoc["image_name_with_tag_list"] = nil
		secretScanDoc["scan_id_list"] = nil
		secretScanDoc["time_stamp"] = timestamp
		secretScanDoc["@timestamp"] = currTime
		secretScanDoc["node_id"] = imageName
		secretScanDoc["node_name"] = imageName
		secretScanDoc["scan_id"] = scanId
		values := reflect.ValueOf(*secret)
		typeOfS := values.Type()
		for index := 0; index < values.NumField(); index++ {
			if values.Field(index).CanInterface() {
				secretScanDoc[typeOfS.Field(index).Name] = values.Field(index).Interface()
			}
		}
		byteJson, err := json.Marshal(secretScanDoc)
		if err != nil {
			fmt.Println("Error in marshalling secret result object to json:" + err.Error())
			return
		}
		err = output.IngestSecretScanResults(string(byteJson), secretScanIndexName)
		if err != nil {
			fmt.Println("Error in sending data to secretScanIndex:" + err.Error())
		}
	}
	if err == nil {
		secretScanLogDoc["scan_status"] = scanStatusComplete
	} else {
		secretScanLogDoc["scan_status"] = scanStatusError
		secretScanLogDoc["scan_message"] = err.Error()
	}
	secretScanLogDoc["time_stamp"] = timestamp
	secretScanLogDoc["@timestamp"] = currTime
	byteJson, err = json.Marshal(secretScanLogDoc)
	if err != nil {
		fmt.Println("Error in marshalling secretScanLogDoc to json:" + err.Error())
		return
	}
	err = output.IngestSecretScanResults(string(byteJson), secretScanLogsIndexName)
	if err != nil {
		fmt.Println("Error in sending data to secretScanLogsIndex:" + err.Error())
	}
}

func RunHttpServer(listenPort string) error {
	http.Handle("/secret-scan", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		runSecretScan(writer, request)
	}))
	http.HandleFunc("/secret-scan/test", func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprintf(writer, "Hello World!")
	})

	http.ListenAndServe(":"+listenPort, nil)
	fmt.Println("Http Server listening on " + listenPort)
	return nil
}

// operation is prepended to error message in case of error: optional
func runCommand(cmd *exec.Cmd, operation string) (*bytes.Buffer, error) {
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	errorOnRun := cmd.Run()
	if errorOnRun != nil {
		return nil, errors.New(operation + fmt.Sprint(errorOnRun) + ": " + stderr.String())
	}
	return &out, nil
}
