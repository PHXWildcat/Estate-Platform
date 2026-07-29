# syntax=docker/dockerfile:1.7
#
# TLS terminator for the stack's AWS endpoint. See entrypoint.sh for why the
# production profile needs it: the production config refuses a plaintext
# AWS_ENDPOINT_URL, and the alternative to real TLS would be weakening that
# guard — which is the one thing this milestone must not do.
FROM nginx:1.27-alpine

RUN apk add --no-cache openssl
COPY infra/docker/aws-tls/nginx.conf /etc/nginx/nginx.conf
COPY infra/docker/aws-tls/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 443
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
