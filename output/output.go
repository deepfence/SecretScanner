package output

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"
)

const (
	Indent = "  " // Indentation for Json printing
)

type SecretFound struct {
	LayerID                                       string  `json:"Image Layer ID,omitempty"`
	RuleID                                        int     `json:"Matched Rule ID,omitempty"`
	RuleName                                      string  `json:"Matched Rule Name,omitempty"`
	PartToMatch                                   string  `json:"Matched Part,omitempty"`
	Match                                         string  `json:"String to Match,omitempty"`
	Regex                                         string  `json:"Signature to Match,omitempty"`
	Severity                                      string  `json:"Severity,omitempty"`
	SeverityScore                                 float64 `json:"Severity Score,omitempty"`
	MatchFromByte                                 int     `json:"Starting Index of Matched Content,omitempty"`
	MatchToByte                                   int     `json:"Ending Index of Matched Content,omitempty"`
	CompleteFilename                              string  `json:"Full File Name,omitempty"`
	MatchedContents                               string  `json:"Matched Contents,omitempty"`
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
	Timestamp time.Time
	ImageName string `json:"Image Name"`
	ImageId   string `json:"Image ID"`
	Secrets   []SecretFound
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
	file, err := json.MarshalIndent(secretsJson, "", Indent)
	if err != nil {
		fmt.Println("Couldn't format json output", err)
		return err
	}

	err = ioutil.WriteFile(outputFilename, file, os.ModePerm)
	if err != nil {
		fmt.Println("Couldn't write json output to file", err)
		return err
	}

	fmt.Println(string(file))

	return nil
}

func PrintImageJsonHeader(ImageName, ImageId string) {
	fmt.Printf("{\n")
	fmt.Printf(Indent + "\"Timestamp\": \"%s\",\n", time.Now().Format("2006-01-02 15:04:05.000000000"))
	fmt.Printf(Indent + "\"Image Name\": \"%s\",\n", ImageName)
	fmt.Printf(Indent + "\"Image ID\": \"%s\",\n", ImageId)
	fmt.Printf(Indent + "\"Secrets\": [\n")
}

func PrintDirJsonHeader(DirName string) {
	fmt.Printf("{\n")
	fmt.Printf(Indent + "\"Timestamp\": \"%s\",\n", time.Now().Format("2006-01-02 15:04:05.000000000"))
	fmt.Printf(Indent + "\"Directory Name\": \"%s\",\n", DirName)
	fmt.Printf(Indent + "\"Secrets\": [\n")
}

func PrintJsonFooter(DirName string) {
	fmt.Printf(Indent + "\n]\n")
	fmt.Printf("}\n")
}

func PrintJsonSecret(secret SecretFound) {
	Indent3 := Indent + Indent + Indent

	fmt.Printf(Indent + Indent + "{\n")
	fmt.Printf(Indent3 + "\"Image Layer ID\": \"%s\",\n", secret.LayerID)
	fmt.Printf(Indent3 + "\"Matched Rule ID\": \"%d\",\n", secret.RuleID)
	fmt.Printf(Indent3 + "\"Matched Rule Name\": \"%s\",\n", secret.RuleName)
	fmt.Printf(Indent3 + "\"Matched Part\": \"%s\",\n", secret.PartToMatch)
	fmt.Printf(Indent3 + "\"String to Match\": \"%s\",\n", secret.Match)
	fmt.Printf(Indent3 + "\"Signature to Match\": \"%s\",\n", secret.Regex)
	fmt.Printf(Indent3 + "\"Severity\": \"%s\",\n", secret.Severity)
	fmt.Printf(Indent3 + "\"Severity Score\": \"%.2f\",\n", secret.SeverityScore)
	fmt.Printf(Indent3 + "\"Starting Index of Matched Content\": \"%d\",\n", secret.MatchFromByte)
	fmt.Printf(Indent3 + "\"Ending Index of Matched Content\": \"%d\",\n", secret.MatchToByte)
	fmt.Printf(Indent3 + "\"Full File Name\": \"%s\",\n", secret.CompleteFilename)
	fmt.Printf(Indent3 + "\"Matched Contents\": \"%s\"\n", secret.MatchedContents)
	fmt.Printf(Indent + Indent + "}\n")
}