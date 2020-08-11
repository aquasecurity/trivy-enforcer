package harbor

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cloudflare/cfssl/log"
	"github.com/aquasecurity/trivy-enforcer/image"
)

const (
	endpoint = "https://%s/api/v2.0/projects/%s/repositories/%s/artifacts/%s/additions/vulnerabilities"
)

type Report struct {
	Vulnerabilities []interface{} `json:"vulnerabilities"`
}

func Query(ctx context.Context, ref image.Reference) ([]interface{}, error) {
	url := fmt.Sprintf(endpoint, ref.Registry, ref.Namespace, ref.Repository, ref.Tag)
	log.Info(url)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	c := &http.Client{Transport: tr}

	resp, err := c.Do(req.WithContext(ctx))
	if err != nil {
		log.Error(err, "failed to request Harbor")
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status is %s", resp.Status)
	}

	var result map[string]Report
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var vulns []interface{}
	for _, report := range result {
		vulns = append(vulns, report.Vulnerabilities...)
	}

	return vulns, nil
}
