# Stack-test ClamAV signature

`stack-test.ndb` declares one custom signature, `Estate.Stack.TestProbe`,
matching the byte string `ESTATE-STACK-MALWARE-PROBE-7f3a` at any offset in any
file type. It is bind-mounted into the clamd container's database directory
alongside the bundled official database, and clamd loads every file it finds
there.

Why it exists: the standard EICAR test file cannot exercise this platform's
scan gate end to end. EICAR only matches when the string is the START of the
file — and a file starting with plain text fails the documents service's
magic-byte sniffing before any scan runs, while prefixing a PDF/PNG header to
get past sniffing stops it being EICAR. So the sniff gate and the scan gate
can never both pass/trip on the same EICAR fixture, by construction.

The stack test instead uploads a VALID PNG carrying the probe bytes in a
`tEXt` chunk: sniffing admits it (real PNG magic), clamd flags it
(`Estate.Stack.TestProbe FOUND` over the INSTREAM protocol), and the upload
must be rejected 422 `malware_detected` with nothing written anywhere — the
fail-closed path proven with the real scanner.

The pattern is inert data with no meaning to anything but this signature.
