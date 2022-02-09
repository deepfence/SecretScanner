package output

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"
	// "strings"
	"github.com/deepfence/SecretScanner/core"
	pb "github.com/deepfence/agent-plugins-grpc/proto"
	"github.com/fatih/color"
)

const (
	Indent = "  " // Indentation for Json printing
)

type SecretFound struct {
	LayerID               string  `json:"Image Layer ID,omitempty"`
	RuleID                int     `json:"Matched Rule ID,omitempty"`
	RuleName              string  `json:"Matched Rule Name,omitempty"`
	PartToMatch           string  `json:"Matched Part,omitempty"`
	Match                 string  `json:"String to Match,omitempty"`
	Regex                 string  `json:"Signature to Match,omitempty"`
	Severity              string  `json:"Severity,omitempty"`
	SeverityScore         float64 `json:"Severity Score,omitempty"`
	PrintBufferStartIndex int     `json:"Starting Index of Match in Original Content,omitempty"`
	MatchFromByte         int     `json:"Relative Starting Index of Match in Displayed Substring"`
	MatchToByte           int     `json:"Relative Ending Index of Match in Displayed Substring"`
	CompleteFilename      string  `json:"Full File Name,omitempty"`
	MatchedContents       string  `json:"Matched Contents,omitempty"`
}

type SecretstOutput interface {
	WriteSecrets(string) error
}

type JsonDirSecretsOutput struct {
	Timestamp time.Time
	DirName   string `json:"Directory Name"`
	Secrets   []SecretFound
}

type JsonImageSecretsOutput struct {
	Timestamp 	time.Time
	ImageName 	string `json:"Image Name"`
	ImageId   	string `json:"Image ID"`
	ContainerId string `json:"Container ID"`
	Secrets   	[]SecretFound
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

func (imageOutput *JsonImageSecretsOutput) SetSecrets(Secrets []SecretFound) {
	imageOutput.Secrets = Secrets
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

func (dirOutput *JsonDirSecretsOutput) SetSecrets(Secrets []SecretFound) {
	dirOutput.Secrets = Secrets
}

func (dirOutput JsonDirSecretsOutput) WriteSecrets(outputFilename string) error {
	err := printSecretsToJsonFile(dirOutput, outputFilename)
	return err
}

func printSecretsToJsonFile(secretsJson interface{}, outputFilename string) error {
	file, err := json.MarshalIndent(secretsJson, "", Indent)
	if err != nil {
		core.GetSession().Log.Error("printSecretsToJsonFile: Couldn't format json output: %s", err)
		return err
	}

	err = ioutil.WriteFile(outputFilename, file, os.ModePerm)
	if err != nil {
		core.GetSession().Log.Error("printSecretsToJsonFile: Couldn't write json output to file: %s", err)
		return err
	}

	// fmt.Println(string(file))

	return nil
}

func (imageOutput JsonImageSecretsOutput) PrintJsonHeader() {
	fmt.Printf("{\n")
	fmt.Printf(Indent+"\"Timestamp\": \"%s\",\n", time.Now().Format("2006-01-02 15:04:05.000000000 -07:00"))
	fmt.Printf(Indent+"\"Image Name\": \"%s\",\n", imageOutput.ImageName)
	fmt.Printf(Indent+"\"Image ID\": \"%s\",\n", imageOutput.ImageId)
	fmt.Printf(Indent + "\"Secrets\": [\n")
}

func (imageOutput JsonImageSecretsOutput) PrintJsonFooter() {
	printJsonFooter()
}

func (dirOutput JsonDirSecretsOutput) PrintJsonHeader() {
	fmt.Printf("{\n")
	fmt.Printf(Indent+"\"Timestamp\": \"%s\",\n", time.Now().Format("2006-01-02 15:04:05.000000000 -07:00"))
	fmt.Printf(Indent+"\"Directory Name\": \"%s\",\n", dirOutput.DirName)
	fmt.Printf(Indent + "\"Secrets\": [\n")
}

func (dirOutput JsonDirSecretsOutput) PrintJsonFooter() {
	printJsonFooter()
}

func printJsonFooter() {
	fmt.Printf("\n" + Indent + "]\n")
	fmt.Printf("}\n")
}

func PrintColoredSecrets(secrets []SecretFound, isFirstSecret *bool) {
	for _, secret := range secrets {
		printColoredSecretJsonObject(secret, isFirstSecret)
		*isFirstSecret = false
	}
}

// Function to print json object with the matches secret string in color
// @parameters
// secret - Structure with details of the secret found
// isFirstSecret - indicates if some secrets are already printed, used to properly format json
func printColoredSecretJsonObject(secret SecretFound, isFirstSecret *bool) {
	Indent3 := Indent + Indent + Indent

	if *isFirstSecret {
		fmt.Printf(Indent + Indent + "{\n")
	} else {
		fmt.Printf(",\n" + Indent + Indent + "{\n")
	}

	fmt.Printf(Indent3+"\"Image Layer ID\": %s,\n", jsonMarshal(secret.LayerID))
	fmt.Printf(Indent3+"\"Matched Rule ID\": %d,\n", secret.RuleID)
	fmt.Printf(Indent3+"\"Matched Rule Name\": %s,\n", jsonMarshal(secret.RuleName))
	fmt.Printf(Indent3+"\"Matched Part\": %s,\n", jsonMarshal(secret.PartToMatch))
	fmt.Printf(Indent3+"\"String to Match\": %s,\n", jsonMarshal(secret.Match))
	fmt.Printf(Indent3+"\"Signature to Match\": %s,\n", jsonMarshal(secret.Regex))
	fmt.Printf(Indent3+"\"Severity\": %s,\n", jsonMarshal(secret.Severity))
	fmt.Printf(Indent3+"\"Severity Score\": %.2f,\n", secret.SeverityScore)
	fmt.Printf(Indent3+"\"Starting Index of Match in Original Content\": %d,\n", secret.PrintBufferStartIndex)
	fmt.Printf(Indent3+"\"Relative Starting Index of Match in Displayed Substring\": %d,\n", secret.MatchFromByte)
	fmt.Printf(Indent3+"\"Relative Ending Index of Match in Displayed Substring\": %d,\n", secret.MatchToByte)
	fmt.Printf(Indent3+"\"Full File Name\": %s,\n", jsonMarshal(secret.CompleteFilename))
	match := secret.MatchedContents
	from := secret.MatchFromByte
	to := secret.MatchToByte
	prefix := removeFirstLastChar(jsonMarshal(match[0:from]))
	coloredMatch := color.RedString(removeFirstLastChar(jsonMarshal(string(match[from:to]))))
	suffix := removeFirstLastChar(jsonMarshal(match[to:]))
	fmt.Printf(Indent3+"\"Matched Contents\": \"%s%s%s\"\n", prefix, coloredMatch, suffix)

	fmt.Printf(Indent + Indent + "}")
}

func jsonMarshal(input string) string {
	output, _ := json.Marshal(input)
	return string(output)
}

func removeFirstLastChar(input string) string {
	if len(input) <= 1 {
		return input
	}
	return input[1 : len(input)-1]
}

func SecretsToSecretInfos(out []SecretFound) []*pb.SecretInfo {
	res := make([]*pb.SecretInfo, 0)
	for _, v := range out {
		res = append(res, SecretToSecretInfo(v))
	}
	return res
}

func SecretToSecretInfo(out SecretFound) *pb.SecretInfo {
	return &pb.SecretInfo{
		ImageLayerId: out.LayerID,
		Rule: &pb.MatchRule{
			Id:               int32(out.RuleID),
			Name:             out.RuleName,
			Part:             out.PartToMatch,
			StringToMatch:    out.Match,
			SignatureToMatch: out.Regex,
		},
		Match: &pb.Match{
			StartingIndex:         int64(out.PrintBufferStartIndex),
			RelativeStartingIndex: int64(out.MatchFromByte),
			RelativeEndingIndex:   int64(out.MatchToByte),
			FullFilename:          out.CompleteFilename,
			MatchedContent:        jsonMarshal(out.MatchedContents),
		},
		Severity: &pb.Severity{
			Level: out.Severity,
			Score: float32(out.SeverityScore),
		},
	}
}
