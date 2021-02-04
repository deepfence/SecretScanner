package output

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"
)

type SecretFound struct {
	LayerID                                       string  `json:"Image Layer ID,omitempty"`
	RuleID                                        int     `json:"Matched Rule ID,omitempty"`
	RuleName                                      string  `json:"Matched Rule Name,omitempty"`
	PartToMatch                                   string  `json:"Matched Part,omitempty"`
	Match                                         string  `json:"String to Match,omitempty"`
	Regex                                         string  `json:"Regex to Match,omitempty"`
	Severity                                      string  `json:"Severity,omitempty"`
	SeverityScore                                 float64 `json:"Severity Score,omitempty"`
	MatchFromByte                                 int     `json:"Starting Index of Matched Content,omitempty"`
	MatchToByte                                   int     `json:"Ending Index of Matched Content,omitempty"`
	CompleteFilename                              string  `json:"Full File Name,omitempty"`
	MatchedContents                               string  `json:"Matched File Contents,omitempty"`
}

type SecretstOutput interface {
	writeSecrets()
}

type JsonDirSecretsOutput struct {
	Timestamp time.Time
	DirName   string `json:"Directory Name"`
	Secrets   []SecretFound
}

type JsonImageSecretsOutput struct {
	Timestamp          time.Time
	ImageName, ImageId string
	Secrets            []SecretFound
}

func (imageOutput *JsonImageSecretsOutput) SetImageName(imageName string) {
	imageOutput.ImageName = imageName
}

func (imageOutput *JsonImageSecretsOutput) SetImageId(imageId string) {
	imageOutput.ImageId = imageId
}

func (imageOutput *JsonImageSecretsOutput) SetTime() {
	imageOutput.Timestamp = time.Now()
}

func (imageOutput JsonImageSecretsOutput) WriteSecrets(outputFilename string) error {
	err := printSecretsToJsonFile(imageOutput, outputFilename)
	return err
}

func (dirOutput *JsonDirSecretsOutput) SetDirName(dirName string) {
	dirOutput.DirName = dirName
}

func (dirOutput *JsonDirSecretsOutput) SetTime() {
	dirOutput.Timestamp = time.Now()
}

func (dirOutput JsonDirSecretsOutput) WriteSecrets(outputFilename string) error {
	err := printSecretsToJsonFile(dirOutput, outputFilename)
	return err
}

func printSecretsToJsonFile(secretsJson interface{}, outputFilename string) error {
	file, err := json.MarshalIndent(secretsJson, "", " ")
	if err != nil {
		fmt.Println("Couldn't format json output", err)
		return err
	}

	err = ioutil.WriteFile(outputFilename, file, os.ModePerm)
	if err != nil {
		fmt.Println("Couldn't write json output to file", err)
		return err
	}

	return nil
}
