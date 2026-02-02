#!/bin/sh
set -euxo pipefail
cargo build --release --target x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/release/ssphp-github-webhooks terraform/github_webhooks/function_zip/ssphp-github-webhooks
cd terraform/red
terraform apply -auto-approve