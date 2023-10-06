package output

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	pb "github.com/deepfence/agent-plugins-grpc/srcgo"
	"github.com/fatih/color"
	tw "github.com/olekukonko/tablewriter"
	log "github.com/sirupsen/logrus"
)

const (
	Indent = "  " // Indentation for Json printing
)

// severity
const (
	HIGH   = "high"
	MEDIUM = "medium"
	LOW    = "low"
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

type JsonDirSecretsOutput struct {
	Timestamp time.Time
	DirName   string `json:"Directory Name"`
	Secrets   []SecretFound
}

type JsonImageSecretsOutput struct {
	Timestamp   time.Time
	ImageName   string `json:"Image Name"`
	ImageId     string `json:"Image ID"`
	ContainerId string `json:"Container ID"`
	Secrets     []SecretFound
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

func (imageOutput *JsonImageSecretsOutput) GetSecrets() []SecretFound {
	return imageOutput.Secrets
}

func (imageOutput JsonImageSecretsOutput) WriteJson() error {
	return printSecretsToJson(imageOutput)

}

func (imageOutput JsonImageSecretsOutput) WriteTable() error {
	return WriteTableOutput(&imageOutput.Secrets)
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
func (dirOutput *JsonDirSecretsOutput) GetSecrets() []SecretFound {
	return dirOutput.Secrets
}

func (dirOutput JsonDirSecretsOutput) WriteJson() error {
	return printSecretsToJson(dirOutput)
}

func (dirOutput JsonDirSecretsOutput) WriteTable() error {
	return WriteTableOutput(&dirOutput.Secrets)
}

func printSecretsToJson(secretsJson interface{}) error {
	file, err := json.MarshalIndent(secretsJson, "", Indent)
	if err != nil {
		log.Errorf("printSecretsToJsonFile: Couldn't format json output: %s", err)
		return err
	}

	fmt.Println(string(file))

	return nil
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

func WriteTableOutput(report *[]SecretFound) error {
	table := tw.NewWriter(os.Stdout)
	table.SetHeader([]string{"Matched Part", "Rule Name", "Severity", "File Name", "Signature"})
	table.SetHeaderLine(true)
	table.SetBorder(true)
	table.SetAutoWrapText(true)
	table.SetAutoFormatHeaders(true)
	table.SetColMinWidth(0, 10)
	table.SetColMinWidth(1, 10)
	table.SetColMinWidth(2, 10)
	table.SetColMinWidth(3, 20)
	table.SetColMinWidth(4, 20)

	for _, r := range *report {
		table.Append([]string{r.PartToMatch, r.RuleName, r.Severity, r.CompleteFilename, r.Regex})
	}
	table.Render()
	return nil
}

type SevCount struct {
	Total  int
	High   int
	Medium int
	Low    int
}

func CountBySeverity(report []SecretFound) SevCount {
	detail := SevCount{}

	for _, r := range report {
		detail.Total += 1
		switch r.Severity {
		case HIGH:
			detail.High += 1
		case MEDIUM:
			detail.Medium += 1
		case LOW:
			detail.Low += 1
		}
	}

	return detail
}

func ExitOnSeverity(severity string, count int, failOnCount int) {
	log.Debugf("ExitOnSeverity severity=%s count=%d failOnCount=%d",
		severity, count, failOnCount)
	if count >= failOnCount {
		if len(severity) > 0 {
			msg := "Exit secret scan. Number of %s secrets (%d) reached/exceeded the limit (%d).\n"
			fmt.Printf(msg, severity, count, failOnCount)
			os.Exit(1)
		}
		msg := "Exit secret scan. Number of secrets (%d) reached/exceeded the limit (%d).\n"
		fmt.Printf(msg, count, failOnCount)
		os.Exit(1)
	}
}

func FailOn(details SevCount, failOnHighCount int, failOnMediumCount int, failOnLowCount int, failOnCount int) {
	if failOnHighCount > 0 {
		ExitOnSeverity(HIGH, details.High, failOnHighCount)
	}
	if failOnMediumCount > 0 {
		ExitOnSeverity(MEDIUM, details.Medium, failOnMediumCount)
	}
	if failOnLowCount > 0 {
		ExitOnSeverity(LOW, details.Low, failOnLowCount)
	}
	if failOnCount > 0 {
		ExitOnSeverity("", details.Total, failOnCount)
	}
}
