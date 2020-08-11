package webhook

import (
	"context"
	"fmt"
	"net/http"


	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/aquasecurity/trivy-enforcer/harbor"
	aquasecurityv1alpha1 "github.com/aquasecurity/trivy-enforcer/api/v1alpha1"
	"github.com/aquasecurity/trivy-enforcer/image"
	"github.com/aquasecurity/trivy-enforcer/opa"
)

const (
	opaURL     = "http://opa.opa"
	trivyPath  = "/v1/data/kubernetes/validating/trivy/deny"
	harborPath = "/v1/data/kubernetes/validating/harbor/deny"
)

var (
	log = ctrl.Log.WithName("validator")

	ErrForbidden = xerrors.New("container forbidden")
)

// +kubebuilder:webhook:path=/validate-v1-pod,mutating=false,failurePolicy=fail,groups="",resources=pods,verbs=create;update,versions=v1,name=vpod.kb.io

// PodValidator validates Pods
type PodValidator struct {
	Client  client.Client
	decoder *admission.Decoder
}

// PodValidator admits a pod iff a specific annotation exists.
func (v *PodValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	pod := &corev1.Pod{}

	err := v.decoder.Decode(req, pod)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	log.Info("Validating webhook", "pod name", pod.Name)
	for _, c := range pod.Spec.Containers {
		ref, err := image.ParseReference(c.Image)
		if err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}

		var inputs []interface{}
		var path string
		if ref.Registry == "core.harbor.domain" {
			log.Info("Querying harbor...")
			vulns, err := harbor.Query(ctx, ref)
			if err != nil {
				return admission.Errored(http.StatusInternalServerError, err)
			}
			log.Info("harbor result", "length", len(vulns))
			inputs = append(inputs, vulns...)
			path = harborPath
		} else {
			selector := labels.Set{
				"registry":   ref.Registry,
				"namespace":  ref.Namespace,
				"repository": ref.Repository,
				"tag":        ref.Tag,
				"digest":     ref.Digest,
			}

			var vulnList aquasecurityv1alpha1.ImageVulnerabilityList
			err = v.Client.List(ctx, &vulnList, &client.ListOptions{
				LabelSelector: labels.SelectorFromSet(selector),
			})
			if err != nil {
				return admission.Errored(http.StatusInternalServerError, err)
			}

			if len(vulnList.Items) == 0 {
				return admission.Denied(fmt.Sprintf("no scan result for image %s", c.Image))
			}

			for _, item := range vulnList.Items {
				for _, v := range item.Status.Vulnerabilities {
					inputs = append(inputs, v)
				}
			}
			path = trivyPath
		}

		log.Info("Evaluating vulnerabilities", "image name", c.Image)
		if err = evalVulnerabilities(ctx, path, c.Image, inputs); err != nil {
			log.Error(err, "evalVulnerabilities")
			if xerrors.Is(err, ErrForbidden) {
				return admission.Denied(err.Error())
			}
			return admission.Errored(http.StatusInternalServerError, err)
		}

	}
	return admission.Allowed("")
}

func evalVulnerabilities(ctx context.Context, path string, image string, inputs []interface{}) error {
	log.Info("eval", "path", path, "input", len(inputs))
	o := opa.New(opaURL)
	limit := make(chan struct{}, 10)

	eg, ctx := errgroup.WithContext(ctx)
	for _, input := range inputs {
		vuln := input
		eg.Go(func() error {
			limit <- struct{}{}
			defer func() { <-limit }()

			result, err := o.Eval(ctx, path, vuln)
			if err != nil {
				return err
			}

			if len(result) != 0 {
				return xerrors.Errorf("%s in image %s: %w", result[0], image, ErrForbidden)
			}
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return err
	}

	return nil
}

// podValidator implements admission.DecoderInjector.
// A decoder will be automatically injected.

// InjectDecoder injects the decoder.
func (v *PodValidator) InjectDecoder(d *admission.Decoder) error {
	v.decoder = d
	return nil
}
