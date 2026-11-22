# Provenance layer design (age-proof-v1)

## Goal

Add an accountable provenance layer *around* an existing age ciphertext,
without changing a single byte of the inner age file and without adding any
new external dependency. Files without the layer keep working exactly as
before; files with the layer can be verified against a receiver-maintained
trust list before any plaintext byte is produced.

## Binary envelope

```
----- (text, line oriented, "\n" terminated) -----------------------------
age-proof-v1
-> signer <KEYID>
<b64 wrapped public key, short last line>
-> ed25519 <KEYID>
<b64 wrapped signature, short last line>
... one pair per signer ...
-> end <inner size in decimal> <base64 SHA-256 of inner>
----- (binary) -----------------------------------------------------------
<inner age ciphertext, exactly inner size bytes>
```

There is no trailing data: anything after the declared inner size is an
error, so truncation and concatenation of two files are both rejected.

The 64-byte magic `"age-proof-v1\n"` (padded with ASCII spaces to 63 bytes
plus the newline) never collides with the age header intro
`"age-encryption.org/v1\n"` nor with the armored age PEM header.

## What is signed

For each signer, the signed message is a canonical, unambiguous byte string:

```
"age-proof-v1\n" ||
"inner-size:" || decimal || "\n" ||
"inner-sha256:" || lowercase hex || "\n" ||
"signer:" || lowercase hex KEYID || "\n" ||
"created:" || decimal unix seconds || "\n" ||
"expires:" || decimal unix seconds or "0" || "\n"
```

The signature is plain Ed25519 over that message. The message commits to
every inner byte via SHA-256, to the inner length (truncation / append
detection even before hashing finishes), and to the signer's own key id
(SHA-256 of the raw 32-byte Ed25519 public key), so a signature cannot be
re-bound to another key.

Streaming: the inner payload is hashed with SHA-256 in 32 KiB chunks while
it is read or written; only the 32-byte digest is ever retained. Header
parsing is capped at 2 MiB and 1024 signer stanzas.

## Trust list

Receiver-maintained UTF-8 text file. One entry per line, blank lines and
`#` comments ignored:

```
ssh-ed25519 AAAA... optional label
age-proof-1<bech32 of raw 32-byte key> optional label
revoked: ssh-ed25519 AAAA...
expires: 2030-01-01T00:00:00Z ssh-ed25519 AAAA...
```

Identity is established *only* by this file; the envelope never carries a
self-asserted name. An unreadable or empty trust list is a failure.

## Failure taxonomy (distinct exit codes)

| Condition | Error | Exit code |
|---|---|---|
| input has no proof envelope | ErrProofMissing | 3 |
| envelope malformed / signature crypto-invalid / digest mismatch / truncation / append / cross-file move | ErrProofInvalid | 4 |
| signer not in trust list | ErrSignerUnknown | 5 |
| signer in trust list but revoked | ErrSignerRevoked | 6 |
| proof past its expires timestamp / signer trust expired | ErrProofExpired | 7 |
| trust list unreadable or contains no usable entries | ErrTrustListUnavailable | 2 |

## Text armor

PEM-style `-----BEGIN AGE PROVENANCE FILE-----` /
`-----END AGE PROVENANCE FILE-----`, 64-column strict base64 of the whole
binary envelope. An age reader that does not know this layer sees an
unknown PEM type and fails cleanly; `age-proof unwrap` recovers the exact
inner age ciphertext, which the unmodified `age -d` then decrypts.

## Streaming decrypt semantics

1. Detect envelope by magic (armored first, then binary). No envelope ->
   legacy path, behavior unchanged.
2. Verify the full envelope against the trust list while streaming the
   inner ciphertext to either a re-opened regular file or a 0600 temp file
   (stdin case). The output writer is a lazy opener: it is not created
   until verification succeeds, so no partial plaintext and no
   half-written output file can remain.
3. Only then run the ordinary age decryption over the verified inner
   stream.

Memory stays bounded by the 32 KiB copy buffer, the streaming hash state,
and the capped header regardless of file size.
