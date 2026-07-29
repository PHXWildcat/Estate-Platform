#!/bin/bash
# LocalStack bootstrap: the KMS keys and S3 bucket the services ASSUME exist.
#
# Nothing in the repo creates them. AwsKmsProvider only calls GenerateDataKey
# and Decrypt against an existing keyId; S3ObjectStore only Put/Get/Head
# against an existing bucket. Without this every key-holding service fails on
# its first encrypt, which is its first write.
#
# SIX INDEPENDENT KEYS, one per service KEK, not one shared key. The alias is
# baked into the KMS EncryptionContext (`estate:kek`), so a DEK wrapped for one
# domain cannot be unwrapped under another — that binding is real here and the
# stack test asserts it. What is NOT real here is the IAM grant that would stop
# a service from ASKING: LocalStack Community does not enforce IAM. Six keys
# model the boundary; they do not prove it. See the stack README's limits.
#
# Runs on every LocalStack start (the init hook is re-executed), so every step
# must be idempotent.
set -euo pipefail

REGION="${AWS_DEFAULT_REGION:-us-east-1}"
BUCKET="${STACK_OBJECT_STORE_BUCKET:-estate-documents-local}"

# One alias per service that holds key material. vault (Zone A — the server can
# decrypt nothing) and audit (hash chain, no ciphertext) are deliberately absent.
ALIASES=(
  "alias/estate-identity-kek"
  "alias/estate-profile-kek"
  "alias/estate-assets-kek"
  "alias/estate-plaid-kek"
  "alias/estate-documents-kek"
  "alias/estate-settlement-kek"
)

echo "[stack-init] provisioning KMS keys in ${REGION}"
for alias in "${ALIASES[@]}"; do
  if awslocal kms describe-key --key-id "${alias}" --region "${REGION}" >/dev/null 2>&1; then
    echo "[stack-init]   ${alias} already exists"
    continue
  fi
  key_id="$(awslocal kms create-key \
    --region "${REGION}" \
    --description "estate local stack ${alias}" \
    --query 'KeyMetadata.KeyId' --output text)"
  awslocal kms create-alias \
    --region "${REGION}" \
    --alias-name "${alias}" \
    --target-key-id "${key_id}"
  echo "[stack-init]   created ${alias} -> ${key_id}"
done

echo "[stack-init] provisioning S3 bucket ${BUCKET}"
if awslocal s3api head-bucket --bucket "${BUCKET}" --region "${REGION}" >/dev/null 2>&1; then
  echo "[stack-init]   ${BUCKET} already exists"
else
  awslocal s3 mb "s3://${BUCKET}" --region "${REGION}"
  echo "[stack-init]   created ${BUCKET}"
fi

# A marker the compose healthcheck polls. LocalStack reports healthy as soon as
# its services are up, which is BEFORE this hook finishes — so a service that
# waited only on LocalStack's own health could still race key creation and fail
# its first encrypt.
touch /tmp/stack-init-complete
echo "[stack-init] done"
