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

# INVALIDATE THE HEALTH MARKER FIRST. It lives on the container filesystem,
# which survives `docker restart` even though LocalStack's state does not — so a
# marker left from the previous run made compose report a container that was
# healthy, keyless, and about to fail every service's first encrypt. The marker
# must mean "THIS run provisioned successfully", which means clearing it before
# doing anything that can fail.
rm -f /tmp/stack-init-complete

# ---------------------------------------------------------------------------
# KEY LOSS IS DETECTED, NOT SURVIVED.
#
# LocalStack Community cannot persist state (PERSISTENCE is a Pro feature), and
# this was MEASURED rather than assumed: with the volume mounted, a plain
# `docker restart` leaves zero KMS aliases, an empty S3, and a previously
# wrapped DEK failing Decrypt with `NotFoundException — Key ... does not exist`.
# The volume holds the state DIRECTORY; the state is not in it.
#
# The Postgres volumes, however, do persist. So a restart of this one container
# leaves every wrapped DEK in those clusters permanently unopenable and every
# `document_versions.object_key` dangling — with no error at restart time. The
# symptom arrives later as decrypt failures in a stack that looks healthy, which
# is the worst way to learn it.
#
# The epoch file lives on the VOLUME, which does persist. Its presence with no
# KMS aliases behind it means exactly one thing: this container was provisioned
# once and has since lost its key material. Refusing to come up is the honest
# response — the alternative is re-minting keys under the same aliases and
# handing the services a stack that quietly cannot read its own data.
# ---------------------------------------------------------------------------
EPOCH_FILE=/var/lib/localstack/stack-epoch
if [ -f "${EPOCH_FILE}" ] && \
   ! awslocal kms describe-key --key-id alias/estate-identity-kek --region "${REGION}" >/dev/null 2>&1
then
  if [ "${STACK_ALLOW_KEY_LOSS:-0}" = '1' ]; then
    echo "[stack-init] WARNING: key material was lost since epoch $(cat "${EPOCH_FILE}")."
    echo "[stack-init] STACK_ALLOW_KEY_LOSS=1 — re-provisioning anyway. Existing ciphertext is UNREADABLE."
    rm -f "${EPOCH_FILE}"
  else
    echo '[stack-init] ============================================================'
    echo '[stack-init] REFUSING TO START: LocalStack lost its KMS keys and S3'
    echo '[stack-init] objects, but the Postgres volumes still hold ciphertext'
    echo '[stack-init] and object keys that referenced them. Re-provisioning now'
    echo '[stack-init] would mint NEW keys under the SAME aliases and give you a'
    echo '[stack-init] stack that boots cleanly and cannot decrypt its own data.'
    echo '[stack-init]'
    echo "[stack-init] Provisioned at: $(cat "${EPOCH_FILE}")"
    echo '[stack-init]'
    echo '[stack-init] The data volumes are ONE UNIT. Reset them together:'
    echo '[stack-init]     pnpm stack:reset      # compose down -v'
    echo '[stack-init]'
    echo '[stack-init] If you know the clusters are empty (or you do not care):'
    echo '[stack-init]     STACK_ALLOW_KEY_LOSS=1 in the localstack environment'
    echo '[stack-init] ============================================================'
    exit 1
  fi
fi

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

# The epoch: written to the VOLUME (which persists) after a successful
# provision, so the next start can tell "never provisioned" from "provisioned
# and then lost its keys". See the guard at the top.
date -u +%Y-%m-%dT%H:%M:%SZ > "${EPOCH_FILE}"

# A marker the compose healthcheck polls. Written to /tmp, NOT the volume, so it
# vanishes with the container: LocalStack reports healthy as soon as its
# services are up, which is BEFORE this hook finishes — a service waiting only
# on LocalStack's own health could still race key creation and fail its first
# encrypt.
touch /tmp/stack-init-complete
echo "[stack-init] done"
