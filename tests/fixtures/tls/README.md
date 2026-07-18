# TLS smoke-test fixtures

The smoke test creates short-lived self-signed certificates in a temporary directory. No private keys are checked into the repository. Production deployments should mount `/etc/bearust/tls` read-only and keep private keys mode `0600`.
