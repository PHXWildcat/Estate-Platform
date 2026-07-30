# syntax=docker/dockerfile:1.7
#
# OCR sidecar: Tesseract behind a two-route HTTP surface.
#
# WHY A SIDECAR rather than a library in the documents service. The bytes it
# parses are an attacker-supplied upload and the parser is a large C++ codebase,
# so it gets a process boundary instead of a place in the dependency tree of the
# service that handles untrusted input. That is the same call already made three
# times in this repo: clamd on node:net, the Plaid webhook verifier on
# node:crypto, and the in-repo template renderer — never a library on a path
# that touches hostile bytes.
#
# The protocol is deliberately tiny, because it is also untrusted-input surface:
#   POST /ocr    raw bytes in, {"text": "..."} out
#   GET  /healthz
# TesseractOcr in the documents service validates the response envelope, caps
# its size, and treats the text as inert data — never parsed, never logged.

FROM debian:12-slim

# tesseract-ocr-eng is the language data; without it every recognition returns
# empty and the failure looks like "the scan had no text". Full python3, not
# python3-minimal: minimal omits the stdlib (json, http.server live in
# libpython3-stdlib), and the server imports both.
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
       tesseract-ocr tesseract-ocr-eng python3 wget \
  && rm -rf /var/lib/apt/lists/*

COPY infra/docker/tesseract-server.py /srv/tesseract-server.py

# Unprivileged: the process that runs the parser should not be root even here.
RUN useradd --system --uid 65532 --create-home ocr
USER ocr
EXPOSE 8884
CMD ["python3", "/srv/tesseract-server.py"]
