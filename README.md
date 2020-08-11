# trivy-enforcer

**EXPERIMENTAL**

Kubernetes Operator for Image Assurance

It works as 
- Admission Controller
  - protecting unsafe images from being deployed
- Custom Controller
  - watching ImageVulnerability CRD and scanning the image in the custom resource automatically

## Setup

```
$ kubectl apply -f manifests/opa.yaml
$ kubectl apply -f manifests/cert-manager.yaml
$ export IMG=your_account/controller:latest
$ make docker-push
$ make deploy
```

## Development

```
$ kubectl apply -f manifests/opa.yaml
$ kubectl apply -f manifests/cert-manager.yaml
$ skaffold dev
```
