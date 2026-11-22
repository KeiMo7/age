// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package provenance

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"filippo.io/age/internal/format"
)

const (
	// Version is the only supported envelope version line.
	Version = "age-proof-v1"

	intro = Version + "\n"

	maxHeaderBytes      = 2 << 20
	maxSignerStanzas    = 1024
	maxLineLength       = 8 << 10
	maxPayloadArguments = 8

	// copyBufferSize bounds the memory used while streaming the inner
	// payload. Nothing in this package grows with the file size.
	copyBufferSize = 32 << 10
)

// KeyIDLength is the length of a signer key id: the SHA-256 digest of the
// raw 32-byte Ed25519 public key.
const KeyIDLength = sha256.Size

// Signer is one Ed25519 signature over an envelope, together with the
// public key needed to check it.
type Signer struct {
	// PublicKey is the raw 32-byte Ed25519 public key.
	PublicKey ed25519.PublicKey
	// KeyID is SHA-256(PublicKey), also used as the stanza argument.
	KeyID []byte
	// Signature is the Ed25519 signature over the canonical binding message.
	Signature []byte
	// Created is the signing time recorded by the signer and covered by
	// the signature.
	Created time.Time
	// Expires is the optional expiration covered by the signature; the
	// zero value means no expiration.
	Expires time.Time
}

// Envelope is a parsed age-proof-v1 header.
type Envelope struct {
	Signers []*Signer
	// InnerSize is the exact, signed length of the inner ciphertext.
	InnerSize int64
	// InnerDigest is the signed SHA-256 of the inner ciphertext.
	InnerDigest []byte

	// headerBytes is how many envelope header bytes precede the binary
	// inner payload.
	headerBytes int64
}

// HeaderBytes reports how many envelope header bytes precede the inner
// payload.
func (e *Envelope) HeaderBytes() int64 { return e.headerBytes }

var b64 = base64.RawStdEncoding.Strict()

func encodeBody(b []byte) string { return b64.EncodeToString(b) }

func decodeBody(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\n\r") {
		return nil, errors.New("unexpected newline in body")
	}
	return b64.DecodeString(s)
}

// signedMessage builds the canonical, non-malleable message each signer
// signs. Every field is length-delimited by a label and a newline so no
// ambiguity is possible.
func signedMessage(innerSize int64, innerDigest, keyID []byte, created, expires int64) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s\n", Version)
	fmt.Fprintf(&b, "inner-size:%d\n", innerSize)
	fmt.Fprintf(&b, "inner-sha256:%x\n", innerDigest)
	fmt.Fprintf(&b, "signer:%x\n", keyID)
	fmt.Fprintf(&b, "created:%d\n", created)
	fmt.Fprintf(&b, "expires:%d\n", expires)
	return b.Bytes()
}

// marshalHeader writes the line-oriented envelope header (everything up to,
// but not including, the binary inner payload).
func marshalHeader(w io.Writer, signers []*Signer, innerSize int64, innerDigest []byte) error {
	if _, err := io.WriteString(w, intro); err != nil {
		return err
	}
	for _, s := range signers {
		if _, err := fmt.Fprintf(w, "-> signer %x\n", s.KeyID); err != nil {
			return err
		}
		if err := writeWrappedBody(w, s.PublicKey); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "-> ed25519 %x %d", s.KeyID, s.Created.Unix()); err != nil {
			return err
		}
		if !s.Expires.IsZero() {
			if _, err := fmt.Fprintf(w, " %d", s.Expires.Unix()); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(w, "\n"); err != nil {
			return err
		}
		if err := writeWrappedBody(w, s.Signature); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "-> end %d %x\n", innerSize, innerDigest); err != nil {
		return err
	}
	return nil
}

// writeWrappedBody emits base64 body lines of at most format.BytesPerLine,
// ending with a short line, matching age stanza body conventions.
func writeWrappedBody(w io.Writer, body []byte) error {
	enc := format.NewWrappedBase64Encoder(b64, w)
	if _, err := enc.Write(body); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

// limitedLineReader bounds header size uniformly, like age's headerReader.
type limitedLineReader struct {
	r *bufio.Reader
	n int
}

func (l *limitedLineReader) ReadString(delim byte) (string, error) {
	line, err := l.r.ReadString(delim)
	l.n += len(line)
	if l.n > maxHeaderBytes {
		return "", fmt.Errorf("proof header exceeds %d bytes", maxHeaderBytes)
	}
	if len(line) > maxLineLength {
		return "", fmt.Errorf("proof header line exceeds %d bytes", maxLineLength)
	}
	return line, err
}

// parseHeader reads an age-proof-v1 header from br and returns the envelope
// with br positioned at the first inner payload byte. The caller must keep
// using br afterwards: this function deliberately shares the caller's
// buffered reader so over-read header bytes are never lost.
func parseHeader(br *bufio.Reader) (*Envelope, error) {
	lr := &limitedLineReader{r: br}

	line, err := lr.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read version line: %v", ErrProofInvalid, err)
	}
	if line != intro {
		return nil, fmt.Errorf("%w: unexpected version line %q", ErrProofInvalid, strings.TrimRight(line, "\n"))
	}

	e := &Envelope{}

	for {
		line, err := lr.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("%w: failed to read header line: %v", ErrProofInvalid, err)
		}
		trimmed := strings.TrimSuffix(line, "\n")
		trimmed = strings.TrimSuffix(trimmed, "\r")
		args := strings.Split(trimmed, " ")
		if len(args) < 2 || args[0] != "->" {
			return nil, fmt.Errorf("%w: malformed stanza opening line", ErrProofInvalid)
		}
		if len(args) > maxPayloadArguments {
			return nil, fmt.Errorf("%w: too many stanza arguments", ErrProofInvalid)
		}

		switch args[1] {
		default:
			return nil, fmt.Errorf("%w: unknown stanza type %q", ErrProofInvalid, args[1])

		case "signer":
			if len(e.Signers) == maxSignerStanzas {
				return nil, fmt.Errorf("%w: too many signer stanzas", ErrProofInvalid)
			}
			if len(args) != 3 {
				return nil, fmt.Errorf("%w: malformed signer stanza", ErrProofInvalid)
			}
			keyID, ok := decodeHex(args[2], KeyIDLength)
			if !ok {
				return nil, fmt.Errorf("%w: malformed signer key id", ErrProofInvalid)
			}
			pub, err := readWrappedBody(lr, ed25519.PublicKeySize)
			if err != nil {
				return nil, err
			}
			if sha256.Sum256(pub) != [KeyIDLength]byte(keyID) {
				return nil, fmt.Errorf("%w: signer key id does not match public key", ErrProofInvalid)
			}
			e.Signers = append(e.Signers, &Signer{
				PublicKey: ed25519.PublicKey(pub),
				KeyID:     keyID,
			})

		case "ed25519":
			// -> ed25519 <keyid> <created> [<expires>]
			if len(args) != 4 && len(args) != 5 {
				return nil, fmt.Errorf("%w: malformed signature stanza", ErrProofInvalid)
			}
			if len(e.Signers) == 0 {
				return nil, fmt.Errorf("%w: signature without signer", ErrProofInvalid)
			}
			s := e.Signers[len(e.Signers)-1]
			keyID, ok := decodeHex(args[2], KeyIDLength)
			if !ok || !bytes.Equal(keyID, s.KeyID) {
				return nil, fmt.Errorf("%w: signature key id does not match signer", ErrProofInvalid)
			}
			created, err := strconv.ParseInt(args[3], 10, 64)
			if err != nil || created < 0 {
				return nil, fmt.Errorf("%w: malformed signature timestamp", ErrProofInvalid)
			}
			s.Created = time.Unix(created, 0).UTC()
			if len(args) == 5 {
				expires, err := strconv.ParseInt(args[4], 10, 64)
				if err != nil || expires <= created {
					return nil, fmt.Errorf("%w: malformed signature expiration", ErrProofInvalid)
				}
				s.Expires = time.Unix(expires, 0).UTC()
			}
			sig, err := readWrappedBody(lr, ed25519.SignatureSize)
			if err != nil {
				return nil, err
			}
			s.Signature = sig

		case "end":
			if len(args) != 4 {
				return nil, fmt.Errorf("%w: malformed end stanza", ErrProofInvalid)
			}
			size, err := strconv.ParseInt(args[2], 10, 64)
			if err != nil || size < 0 || size > math.MaxInt64 {
				return nil, fmt.Errorf("%w: malformed inner size", ErrProofInvalid)
			}
			digest, ok := decodeHex(args[3], sha256.Size)
			if !ok {
				return nil, fmt.Errorf("%w: malformed inner digest", ErrProofInvalid)
			}
			if len(e.Signers) == 0 {
				return nil, fmt.Errorf("%w: envelope carries no signatures", ErrProofInvalid)
			}
			e.InnerSize = size
			e.InnerDigest = digest
			// lr.n counts every header byte consumed, including all body
			// lines and this closing line: the single source of truth for
			// where the binary payload begins.
			e.headerBytes = int64(lr.n)
			return e, nil
		}
	}
}

// readWrappedBody reads the short-line-terminated base64 body following a
// stanza opening line and returns the decoded bytes.
func readWrappedBody(lr *limitedLineReader, expect int) ([]byte, error) {
	var body []byte
	for {
		line, err := lr.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("%w: failed to read stanza body: %v", ErrProofInvalid, err)
		}
		trimmed := strings.TrimSuffix(line, "\n")
		trimmed = strings.TrimSuffix(trimmed, "\r")
		decoded, err := decodeBody(trimmed)
		if err != nil {
			return nil, fmt.Errorf("%w: malformed stanza body: %v", ErrProofInvalid, err)
		}
		if len(decoded) > format.BytesPerLine {
			return nil, fmt.Errorf("%w: stanza body line too long", ErrProofInvalid)
		}
		body = append(body, decoded...)
		if len(decoded) < format.BytesPerLine {
			if len(body) != expect {
				return nil, fmt.Errorf("%w: stanza body has length %d, want %d", ErrProofInvalid, len(body), expect)
			}
			return body, nil
		}
	}
}

func decodeHex(s string, expect int) ([]byte, bool) {
	if len(s) != expect*2 {
		return nil, false
	}
	out := make([]byte, expect)
	for i := range out {
		hi, ok1 := fromHex(s[2*i])
		lo, ok2 := fromHex(s[2*i+1])
		if !ok1 || !ok2 {
			return nil, false
		}
		out[i] = hi<<4 | lo
	}
	return out, true
}

func fromHex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	default:
		return 0, false
	}
}
