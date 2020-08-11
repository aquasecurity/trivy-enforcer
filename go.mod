module github.com/aquasecurity/trivy-enforcer

go 1.14

require (
	github.com/aquasecurity/fanal v0.0.0-20200528202907-79693bf4a058
	github.com/aquasecurity/trivy v0.9.2
	github.com/aquasecurity/trivy-db v0.0.0-20200719151232-94297d005007
	github.com/cloudflare/cfssl v1.4.1
	github.com/go-logr/logr v0.1.0
	github.com/google/go-containerregistry v0.0.0-20200331213917-3d03ed9b1ca2
	github.com/google/wire v0.3.0
	github.com/onsi/ginkgo v1.11.0
	github.com/onsi/gomega v1.8.1
	github.com/spf13/afero v1.2.2
	golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e
	golang.org/x/xerrors v0.0.0-20191204190536-9bdfabe68543
	k8s.io/api v0.17.4
	k8s.io/apimachinery v0.17.4
	k8s.io/client-go v0.17.4
	k8s.io/utils v0.0.0-20191114184206-e782cd3c129f
	sigs.k8s.io/controller-runtime v0.5.0
)
