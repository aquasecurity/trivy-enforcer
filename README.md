# trivy-enforcer

**EXPERIMENTAL**

Kubernetes Operator for Image Assurance

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
