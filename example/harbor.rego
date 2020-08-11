package kubernetes.validating.harbor

deny[msg] {
    input.severity == {"High", "Critical"}[_]
    msg := "forbidden"
}
