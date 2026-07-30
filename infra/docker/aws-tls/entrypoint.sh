#!/bin/sh
# TLS terminator in front of LocalStack.
#
# WHY THIS EXISTS: production config REFUSES a plaintext AWS_ENDPOINT_URL —
# wrapped DEKs and content ciphertext must not cross the wire in the clear.
# LocalStack speaks http. So the production PROFILE of the local stack cannot
# talk to LocalStack directly, and the two ways to "fix" that are:
#
#   (a) weaken the production guard, or accept plaintext in prod mode;
#   (b) give the stack real TLS.
#
# (a) would delete the control this milestone exists to rehearse. This is (b).
# The cert is generated on first boot into a shared volume; the node services
# mount that volume and trust the CA through NODE_EXTRA_CA_CERTS, so TLS
# verification stays ON — nothing sets NODE_TLS_REJECT_UNAUTHORIZED, which
# would be (a) wearing (b)'s clothes.
set -eu

CERT_DIR=/certs
CRT="$CERT_DIR/aws-tls.crt"
KEY="$CERT_DIR/aws-tls.key"

if [ ! -f "$CRT" ] || [ ! -f "$KEY" ]; then
  echo "[aws-tls] generating a self-signed cert for the stack's AWS endpoint"
  # SANs cover every name a service might use for this proxy.
  openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
    -keyout "$KEY" -out "$CRT" \
    -subj "/CN=aws-tls" \
    -addext "subjectAltName=DNS:aws-tls,DNS:localhost,IP:127.0.0.1"
  chmod 644 "$CRT" "$KEY"
else
  echo "[aws-tls] reusing the existing cert"
fi

# A marker the healthcheck polls: the cert must exist before any service that
# trusts it starts, or the first KMS call fails on an unknown CA.
touch "$CERT_DIR/ready"

exec nginx -g 'daemon off;'
