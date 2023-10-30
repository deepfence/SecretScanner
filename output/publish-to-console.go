package output

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	dsc "github.com/deepfence/golang_deepfence_sdk/client"
	oahttp "github.com/deepfence/golang_deepfence_sdk/utils/http"
	log "github.com/sirupsen/logrus"
)

var (
	MgmtConsoleUrl string
	DeepfenceKey   string
)

func init() {
	MgmtConsoleUrl = os.Getenv("MGMT_CONSOLE_URL")
	mgmtConsolePort := os.Getenv("MGMT_CONSOLE_PORT")
	if mgmtConsolePort != "" && mgmtConsolePort != "443" {
		MgmtConsoleUrl += ":" + mgmtConsolePort
	}
	DeepfenceKey = os.Getenv("DEEPFENCE_KEY")
}

func IngestSecretScanResults(secretScanMsg string, index string) error {
	secretScanMsg = strings.Replace(secretScanMsg, "\n", " ", -1)
	postReader := bytes.NewReader([]byte(secretScanMsg))
	retryCount := 0
	httpClient, err := buildClient()
	if err != nil {
		log.Errorf("Error building http client " + err.Error())
		return err
	}
	for {
		httpReq, err := http.NewRequest("POST", "https://"+MgmtConsoleUrl+"/ingest/topics/"+index, postReader)
		if err != nil {
			return err
		}
		httpReq.Close = true
		httpReq.Header.Add("deepfence-key", DeepfenceKey)
		httpReq.Header.Add("Content-Type", "application/vnd.kafka.json.v2+json")
		resp, err := httpClient.Do(httpReq)
		if err != nil {
			return err
		}
		if resp.StatusCode == 200 {
			resp.Body.Close()
			break
		} else {
			if retryCount > 5 {
				errMsg := fmt.Sprintf("Unable to complete request. Got %d ", resp.StatusCode)
				resp.Body.Close()
				return errors.New(errMsg)
			}
			resp.Body.Close()
			retryCount += 1
			time.Sleep(5 * time.Second)
		}
	}
	return nil
}

func buildClient() (*http.Client, error) {
	// Set up our own certificate pool
	tlsConfig := &tls.Config{RootCAs: x509.NewCertPool(), InsecureSkipVerify: true}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     tlsConfig,
			DisableKeepAlives:   false,
			MaxIdleConnsPerHost: 1024,
			DialContext: (&net.Dialer{
				Timeout:   15 * time.Minute,
				KeepAlive: 15 * time.Minute,
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 5 * time.Minute,
		},
		Timeout: 15 * time.Minute,
	}
	return client, nil
}

type Publisher struct {
	client         *oahttp.OpenapiHttpClient
	stopScanStatus chan bool
}

func GetHostname() string {
	name, err := os.Hostname()
	if err != nil {
		return ""
	}
	return name
}

func NewPublisher(url string, port string, key string) (*Publisher, error) {
	client := oahttp.NewHttpsConsoleClient(url, port)
	if err := client.APITokenAuthenticate(key); err != nil {
		return nil, err
	}
	return &Publisher{client: client}, nil
}

func (p *Publisher) SendReport(hostname, image_name, container_id, node_type string) {

	report := dsc.IngestersReportIngestionData{}

	host := map[string]interface{}{
		"node_id":               hostname,
		"host_name":             hostname,
		"node_name":             hostname,
		"node_type":             "host",
		"cloud_region":          "cli",
		"cloud_provider":        "cli",
		"kubernetes_cluster_id": "",
	}
	report.HostBatch = []map[string]interface{}{host}

	if node_type != "" {
		image := map[string]interface{}{
			"docker_image_name_with_tag": image_name,
			"docker_image_id":            image_name,
			"node_id":                    image_name,
			"node_name":                  image_name,
			"node_type":                  node_type,
		}
		s := strings.Split(image_name, ":")
		if len(s) == 2 {
			image["docker_image_name"] = s[0]
			image["docker_image_tag"] = s[1]
		}
		containerImageEdge := map[string]interface{}{
			"source":       hostname,
			"destinations": image_name,
		}
		report.ContainerImageBatch = []map[string]interface{}{image}
		report.ContainerImageEdgeBatch = []map[string]interface{}{containerImageEdge}
	}

	log.Debugf("report: %+v", report)

	req := p.client.Client().TopologyAPI.IngestSyncAgentReport(context.Background())
	req = req.IngestersReportIngestionData(report)

	resp, err := p.client.Client().TopologyAPI.IngestSyncAgentReportExecute(req)
	if err != nil {
		log.Error(err)
	}
	log.Debugf("report response %s", resp.Status)
}

func (p *Publisher) StartScan(node_id, node_type string) string {

	scanTrigger := dsc.ModelSecretScanTriggerReq{
		Filters: *dsc.NewModelScanFilterWithDefaults(),
		NodeIds: []dsc.ModelNodeIdentifier{},
	}

	nodeIds := dsc.ModelNodeIdentifier{NodeId: node_id, NodeType: node_type}
	if node_type != "" {
		nodeIds.NodeType = "host"
	}

	scanTrigger.NodeIds = append(scanTrigger.NodeIds, nodeIds)

	req := p.client.Client().SecretScanAPI.StartSecretScan(context.Background())
	req = req.ModelSecretScanTriggerReq(scanTrigger)
	res, resp, err := p.client.Client().SecretScanAPI.StartSecretScanExecute(req)
	if err != nil {
		log.Error(err)
		return ""
	}
	// defer resp.Body.Close()
	// io.Copy(io.Discard, resp.Body)

	log.Debugf("start scan response: %+v", res)
	log.Debugf("start scan response status: %s", resp.Status)

	return res.GetScanIds()[0]
}

func (p *Publisher) PublishScanStatusMessage(scan_id, message, status string) {
	data := dsc.IngestersSecretScanStatus{}
	data.SetScanId(scan_id)
	data.SetScanStatus(status)
	data.SetScanMessage(message)

	req := p.client.Client().SecretScanAPI.IngestSecretScanStatus(context.Background())
	req = req.IngestersSecretScanStatus([]dsc.IngestersSecretScanStatus{data})

	resp, err := p.client.Client().SecretScanAPI.IngestSecretScanStatusExecute(req)
	if err != nil {
		log.Error(err)
	}

	log.Debugf("publish scan status response: %v", resp)
}

func (p *Publisher) PublishScanError(scan_id, errMsg string) {
	p.PublishScanStatusMessage(scan_id, errMsg, "ERROR")
}

func (p *Publisher) PublishScanStatusPeriodic(scan_id, status string) {
	go func() {
		p.PublishScanStatusMessage(scan_id, "", status)
		ticker := time.NewTicker(30 * time.Second)
		for {
			select {
			case <-ticker.C:
				p.PublishScanStatusMessage(scan_id, "", status)
			case <-p.stopScanStatus:
				return
			}
		}
	}()
}

func (p *Publisher) StopPublishScanStatus() {
	p.stopScanStatus <- true
	time.Sleep(5 * time.Second)
}

func (p *Publisher) IngestSecretScanResults(scan_id string, secrets []SecretFound) error {
	data := []dsc.IngestersSecret{}

	for _, secret := range secrets {
		rule := dsc.NewIngestersSecretRule()
		rule.SetId(int32(secret.RuleID))
		rule.SetName(secret.RuleName)
		rule.SetPart(secret.PartToMatch)
		rule.SetSignatureToMatch(secret.Regex)

		match := dsc.NewIngestersSecretMatch()
		match.SetFullFilename(secret.CompleteFilename)
		match.SetMatchedContent(secret.MatchedContents)
		match.SetRelativeEndingIndex(int32(secret.MatchToByte))
		match.SetRelativeStartingIndex(int32(secret.MatchFromByte))
		match.SetStartingIndex(int32(secret.PrintBufferStartIndex))

		severity := dsc.NewIngestersSecretSeverity()
		severity.SetLevel(secret.Severity)
		severity.SetScore(float32(secret.SeverityScore))

		s := dsc.NewIngestersSecret()
		s.SetImageLayerId(secret.LayerID)
		s.SetRule(*rule)
		s.SetMatch(*match)
		s.SetSeverity(*severity)
		s.SetScanId(scan_id)

		data = append(data, *s)
	}

	req := p.client.Client().SecretScanAPI.IngestSecrets(context.Background())
	req = req.IngestersSecret(data)

	resp, err := p.client.Client().SecretScanAPI.IngestSecretsExecute(req)
	if err != nil {
		log.Error(err)
	}

	log.Debugf("publish scan results response: %v", resp)

	return nil
}
