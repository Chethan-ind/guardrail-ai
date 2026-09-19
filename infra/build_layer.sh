#!/usr/bin/env bash
# Builds the Lambda dependencies layer zip that infra/lambda.tf expects at
# infra/build/dependencies-layer.zip. Run this once before `terraform apply`
# and again any time requirements.txt changes.
set -euo pipefail

cd "$(dirname "$0")/.."

rm -rf infra/build
mkdir -p infra/build/python

python -m pip install --no-user --target infra/build/python boto3 requests python-dotenv

cd infra/build
zip -r dependencies-layer.zip python -x "*.pyc" -x "__pycache__/*"

echo "Built infra/build/dependencies-layer.zip"
