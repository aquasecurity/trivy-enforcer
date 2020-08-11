package operation

import (
	"context"

	"github.com/spf13/afero"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
)

func DownloadDB(appVersion, cacheDir string, quiet, light, skipUpdate bool) error {
	client := initializeDBClient(cacheDir, quiet)
	ctx := context.Background()
	needsUpdate, err := client.NeedsUpdate(appVersion, light, skipUpdate)
	if err != nil {
		return xerrors.Errorf("database error: %w", err)
	}

	if needsUpdate {
		log.Logger.Info("Need to update DB")
		log.Logger.Info("Downloading DB...")
		if err := client.Download(ctx, cacheDir, light); err != nil {
			return xerrors.Errorf("failed to download vulnerability DB: %w", err)
		}
		if err = client.UpdateMetadata(cacheDir); err != nil {
			return xerrors.Errorf("unable to update database metadata: %w", err)
		}
	}

	// for debug
	if err := showDBInfo(cacheDir); err != nil {
		return xerrors.Errorf("failed to show database info: %w", err)
	}
	return nil
}

func showDBInfo(cacheDir string) error {
	m := db.NewMetadata(afero.NewOsFs(), cacheDir)
	metadata, err := m.Get()
	if err != nil {
		return xerrors.Errorf("something wrong with DB: %w", err)
	}
	log.Logger.Debugf("DB Schema: %d, Type: %d, UpdatedAt: %s, NextUpdate: %s",
		metadata.Version, metadata.Type, metadata.UpdatedAt, metadata.NextUpdate)
	return nil
}
