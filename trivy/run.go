package trivy

import (
	"context"
	"net/http"
	"time"

	"github.com/aquasecurity/trivy/pkg/report"

	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
)

const (
	cacheDir   = "/tmp"
	remoteAddr = "http://localhost:4954"
)

func Scan(imageName string) (report.Results, error) {
	if err := log.InitLogger(false, true); err != nil {
		return nil, xerrors.Errorf("failed to initialize a logger: %w", err)
	}

	// configure cache dir
	utils.SetCacheDir(cacheDir)
	log.Logger.Debugf("cache dir:  %s", utils.CacheDir())

	ctx := context.Background()
	remoteCache := cache.NewRemoteCache(remoteAddr, http.Header{})

	cleanup := func() {}
	// scan an image in Docker Engine or Docker Registry
	scanner, cleanup, err := initializeDockerScanner(ctx, imageName, remoteCache,
		client.CustomHeaders{}, client.RemoteURL(remoteAddr), 60*time.Second)
	if err != nil {
		return nil, xerrors.Errorf("unable to initialize the docker scanner: %w", err)
	}
	defer cleanup()

	scanOptions := types.ScanOptions{
		VulnType: []string{"os", "library"},
	}

	results, err := scanner.ScanArtifact(ctx, scanOptions)
	if err != nil {
		return nil, xerrors.Errorf("error in image scan: %w", err)
	}

	vulnClient := initializeVulnerabilityClient()
	for i := range results {
		results[i].Vulnerabilities = vulnClient.Filter(results[i].Vulnerabilities,
			[]dbTypes.Severity{
				dbTypes.SeverityUnknown,
				dbTypes.SeverityLow,
				dbTypes.SeverityMedium,
				dbTypes.SeverityHigh,
				dbTypes.SeverityCritical,
			}, false, "./dummy")
	}

	return results, nil
}
