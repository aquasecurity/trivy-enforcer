package kubernetes.validating.trivy

import data.trivy

deny[msg] {
    not trivy.ignore
    msg := "image forbidden"
}
