package server

import (
	"encoding/json"
	"fmt"
	"github.com/deepfence/SecretScanner/output"
	"github.com/deepfence/SecretScanner/scan"
	"net/http"
	"net/url"
	"reflect"
)

var certPath = "/etc/filebeat/filebeat.crt"

const (
	secretScanIndexName = "secret-scan"
	secretScanLogsIndexName = "secret-scan-logs"
)

func initiateScanImage(writer http.ResponseWriter, request *http.Request) {
	var imageName = request.URL.Query().Get("image_name")
	if imageName == "" {
		http.Error(writer, "{\"error\":\"Image Name is required \"}", http.StatusConflict)
	} else if err := request.ParseForm(); err != nil {
		fmt.Fprintf(writer, "ParseForm() err: %v", err)
		return
	} else {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		fmt.Fprintf(writer, "{\"status\": \"Scan Queued\"}")
		go scanAndPublish(imageName, request.PostForm)
	}
}

func scanAndPublish(imageName string, postForm url.Values) {
	var secretScanLogDoc = make(map[string]interface{})
	secretScanLogDoc["scan_status"] = "IN_PROGRESS"
	secretScanLogDoc["time_stamp"] = getTimestamp()
	secretScanLogDoc["@timestamp"] = getCurrentTime()
	for key, value := range postForm {
		if len(value) > 0 {
			secretScanLogDoc[key] = value[0]
		}
	}
	res, err := scan.ExtractAndScanImage(imageName)
	if err != nil {
		secretScanLogDoc["scan_status"] = "ERROR"
		byteJson, err := json.Marshal(secretScanLogDoc)
		if err != nil {
			fmt.Println("Error in marshalling secret result object to json:" + err.Error())
			return
		}
		err = sendSecretScanDataToLogstash(string(byteJson), secretScanIndexName)
		if err != nil {
			fmt.Println("error in sending data to logstash: " + err.Error())
		}
		return
	}
	timestamp := getTimestamp()
	currTime := getCurrentTime()
	secrets := output.SecretsToSecretInfos(res.Secrets)
	for _, secret := range secrets {
		var secretScanDoc = make(map[string]interface{})
		for key, value := range postForm {
			if len(value) > 0 {
				secretScanLogDoc[key] = value[0]
			}
		}
		secretScanDoc["time_stamp"] = timestamp
		secretScanDoc["@timestamp"] = currTime
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
		err = sendSecretScanDataToLogstash(string(byteJson), secretScanIndexName)
		if err != nil {
			fmt.Println("Error in sending data to secretScanIndex:" + err.Error())
		}
	}
	if err == nil {
		secretScanLogDoc["scan_status"] = "COMPLETE"
	} else {
		secretScanLogDoc["scan_status"] = "ERROR"
		secretScanLogDoc["scan_message"] = err.Error()
	}
	secretScanLogDoc["time_stamp"] = timestamp
	secretScanLogDoc["@timestamp"] = currTime
	byteJson, err := json.Marshal(secretScanLogDoc)
	if err != nil {
		fmt.Println("Error in marshalling secretScanLogDoc to json:" + err.Error())
		return
	}
	err = sendSecretScanDataToLogstash(string(byteJson) , secretScanLogsIndexName)
	if err != nil {
		fmt.Println("Error in sending data to secretScanLogsIndex:" + err.Error())
	}
}

func RunHttpServer(listenPort string) error {
	http.Handle("/scan-image", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		initiateScanImage(writer, request)
	}))

	http.ListenAndServe(":" + listenPort, nil)
	fmt.Println("Http Server listening on " + listenPort)
}
