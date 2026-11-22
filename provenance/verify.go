// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package provenance

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// TrustStatus is the receiver's decision about a signer key.
type TrustStatus int

const (
	// Trusted entries accept proofs made by the key.
	Trusted TrustStatus = iota
	// Revoked entries reject proofs made by the key explicitly.
	Revoked
)

// TrustEntry is one line of a receiver-maintained trust list.
type TrustEntry struct {
	// PublicKey is the raw 32-byte Ed25519 public key.
	PublicKey ed25519.PublicKey
	// KeyID is SHA-256(PublicKey).
	KeyID []byte
	// Label is the optional free-text comment carried by the trust list
	// (never taken from the envelope itself).
	Label string
	// Status is Trusted or Revoked.
	Status TrustStatus
	// Expires optionally limits how long the entry is trusted.
	Expires time.Time
}

// Fingerprint returns the lowercase hex key id used in human-facing
// output.
func (e *TrustEntry) Fingerprint() string {
	return fmt.Sprintf("%x", e.KeyID)
}

// LoadTrustList parses a trust list from r. An empty list, or one with no
// usable entries, is an error: verification must never silently accept.
func LoadTrustList(r io.Reader) ([]*TrustEntry, error) {
	scanner := bufio.NewScanner(io.LimitReader(r, maxHeaderBytes))
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineLength)
	var entries []*TrustEntry
	seen := make(map[string]bool)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entry, err := parseTrustLine(line)
		if err != nil {
			return nil, fmt.Errorf("%w: line %d: %v", ErrTrustListUnavailable, lineNo, err)
		}
		id := string(entry.KeyID)
		if seen[id] {
			return nil, fmt.Errorf("%w: line %d: duplicate key", ErrTrustListUnavailable, lineNo)
		}
		seen[id] = true
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTrustListUnavailable, err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: trust list contains no entries", ErrTrustListUnavailable)
	}
	return entries, nil
}

// LoadTrustListFile opens and parses the trust list at path.
func LoadTrustListFile(path string) ([]*TrustEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTrustListUnavailable, err)
	}
	defer f.Close()
	return LoadTrustList(f)
}

func parseTrustLine(line string) (*TrustEntry, error) {
	status := Trusted
	var expires time.Time
	fields := strings.Fields(line)
	switch fields[0] {
	case "revoked:":
		status = Revoked
		fields = fields[1:]
	case "expires:":
		if len(fields) < 3 {
			return nil, errors.New("malformed expires directive")
		}
		expiry, err := time.Parse(time.RFC3339, fields[1])
		if err != nil {
			return nil, fmt.Errorf("malformed expiration timestamp: %v", err)
		}
		expires = expiry.UTC()
		fields = fields[2:]
	}
	if len(fields) == 0 {
		return nil, errors.New("missing key")
	}
	// An SSH authorized key occupies the first two fields; a native
	// age-proof-1 key occupies only the first. Everything afterward is the
	// human label, which must never reach the key parser.
	keyFields := 1
	if fields[0] == "ssh-ed25519" {
		if len(fields) < 2 {
			return nil, errors.New("malformed SSH public key")
		}
		keyFields = 2
	}
	keyText := strings.Join(fields[:keyFields], " ")
	label := strings.Join(fields[keyFields:], " ")
	pub, err := ParseSignerPublicKey(keyText, label)
	if err != nil {
		return nil, err
	}
	keyID := sha256.Sum256(pub)
	return &TrustEntry{
		PublicKey: pub,
		KeyID:     keyID[:],
		Label:     label,
		Status:    status,
		Expires:   expires,
	}, nil
}

// VerifyParams configures envelope verification.
type VerifyParams struct {
	// Trust is the receiver-maintained list of accepted signers.
	Trust []*TrustEntry
	// Now is the reference time for expiration checks; zero means
	// time.Now.
	Now time.Time
}

// VerifiedSigner describes a signature that passed every check.
type VerifiedSigner struct {
	KeyID     []byte
	Label     string
	Created   time.Time
	Expires   time.Time
	PublicKey ed25519.PublicKey
}

// VerifyResult is the outcome of a successful verification.
type VerifyResult struct {
	// Signers are the signatures that validated against a trusted,
	// non-revoked, non-expired entry.
	Signers []VerifiedSigner
	// InnerSize and InnerDigest record the committed inner payload.
	InnerSize   int64
	InnerDigest []byte
}

// verifyEnvelope checks every signature against the trust list. It returns
// a result as soon as one signer fully validates; otherwise it returns the
// highest-priority failure observed.
func verifyEnvelope(e *Envelope, p VerifyParams) (*VerifyResult, error) {
	now := p.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	if len(p.Trust) == 0 {
		return nil, ErrTrustListUnavailable
	}
	byID := make(map[string]*TrustEntry, len(p.Trust))
	for _, t := range p.Trust {
		byID[string(t.KeyID)] = t
	}

	// Failure priority: invalid > revoked > expired > unknown.
	worst := ErrSignerUnknown
	note := "no signature matched a trusted key"
	promote := func(err error, msg string) {
		rank := func(e error) int {
			switch {
			case errors.Is(e, ErrProofInvalid):
				return 4
			case errors.Is(e, ErrSignerRevoked):
				return 3
			case errors.Is(e, ErrProofExpired):
				return 2
			default:
				return 1
			}
		}
		if rank(err) > rank(worst) {
			worst, note = err, msg
		}
	}

	result := &VerifyResult{InnerSize: e.InnerSize, InnerDigest: e.InnerDigest}
	for _, s := range e.Signers {
		entry, known := byID[string(s.KeyID)]
		if !known {
			promote(ErrSignerUnknown, "unknown signer")
			continue
		}
		if entry.Status == Revoked {
			promote(ErrSignerRevoked, "revoked signer")
			continue
		}
		if !entry.Expires.IsZero() && !now.Before(entry.Expires) {
			promote(ErrProofExpired, "trust entry expired")
			continue
		}
		if !s.Expires.IsZero() && !now.Before(s.Expires) {
			promote(ErrProofExpired, "proof expired")
			continue
		}
		// The signer is trusted; a failing signature on a trusted key is a
		// hard cryptographic failure, not an identity problem.
		msg := signedMessage(e.InnerSize, e.InnerDigest, s.KeyID,
			s.Created.Unix(), expiresUnix(s.Expires))
		if !ed25519.Verify(entry.PublicKey, msg, s.Signature) {
			promote(ErrProofInvalid, "signature verification failed")
			continue
		}
		if !bytes.Equal(entry.PublicKey, s.PublicKey) {
			promote(ErrProofInvalid, "public key mismatch")
			continue
		}
		result.Signers = append(result.Signers, VerifiedSigner{
			KeyID:     s.KeyID,
			Label:     entry.Label,
			Created:   s.Created,
			Expires:   s.Expires,
			PublicKey: s.PublicKey,
		})
	}

	if len(result.Signers) > 0 {
		return result, nil
	}
	return nil, fmt.Errorf("%w: %s", worst, note)
}

func expiresUnix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// Open verifies an age-proof-v1 envelope and returns the exact inner age
// ciphertext as a reader, together with the verification result. The
// caller must call Close on the returned reader when done.
//
// Verification is fully finished — header, every signature, the inner
// length and the SHA-256 of every inner byte — before the returned reader
// yields its first byte, so a rejected envelope can never produce even a
// single byte of (still encrypted) inner output, let alone plaintext.
//
// No plaintext is produced here: Open only validates and hands back the
// still-encrypted inner stream. The ciphertext is staged in a 0600
// temporary file so that a pipe (e.g. standard input) can be verified
// before the inner bytes are consumed; memory stays bounded by the 32 KiB
// stream buffer and the capped header, regardless of file size. Close
// removes the temporary file.
//
// If the input is not an envelope at all, Open wraps ErrProofMissing,
// allowing the caller to fall back to legacy age decryption.
func Open(r io.Reader, p VerifyParams) (io.ReadCloser, *VerifyResult, error) {
	br := bufio.NewReader(r)
	peek, err := br.Peek(len(intro))
	if err != nil || string(peek) != intro {
		return nil, nil, fmt.Errorf("%w: input is not an age-proof-v1 envelope", ErrProofMissing)
	}

	spool, err := os.CreateTemp("", "age-proof-verify-*")
	if err != nil {
		return nil, nil, fmt.Errorf("provenance: failed to create temporary file: %w", err)
	}
	if err := spool.Chmod(0600); err != nil {
		removeSpool(spool)
		return nil, nil, fmt.Errorf("provenance: failed to secure temporary file: %w", err)
	}

	// Stage the whole input through the 0600 spool while parsing and
	// verifying; nothing is returned to the caller on any error path. The
	// buffered reader is shared with parseHeader so bytes over-read while
	// scanning the header stay available for the payload loop below.
	tee := io.TeeReader(br, spool)
	hr := bufio.NewReader(tee)
	env, err := parseHeader(hr)
	if err != nil {
		removeSpool(spool)
		return nil, nil, err
	}
	result, err := verifyEnvelope(env, p)
	if err != nil {
		removeSpool(spool)
		return nil, nil, err
	}

	hash := sha256.New()
	remaining := env.InnerSize
	buf := make([]byte, copyBufferSize)
	for remaining > 0 {
		n, rerr := hr.Read(buf[:min(int64(len(buf)), remaining)])
		if n > 0 {
			hash.Write(buf[:n])
			remaining -= int64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			removeSpool(spool)
			return nil, nil, fmt.Errorf("%w: %v", ErrProofInvalid, rerr)
		}
	}
	if remaining != 0 {
		removeSpool(spool)
		return nil, nil, fmt.Errorf("%w: truncated inner payload", ErrProofInvalid)
	}
	if !bytes.Equal(hash.Sum(nil), env.InnerDigest) {
		removeSpool(spool)
		return nil, nil, fmt.Errorf("%w: inner payload digest mismatch", ErrProofInvalid)
	}
	// No trailing data: this rejects two files concatenated together.
	if n, _ := hr.Read(buf[:1]); n != 0 {
		removeSpool(spool)
		return nil, nil, fmt.Errorf("%w: trailing data after envelope", ErrProofInvalid)
	}

	if _, err := spool.Seek(env.headerBytes, io.SeekStart); err != nil {
		removeSpool(spool)
		return nil, nil, err
	}
	return &spooledInner{File: spool}, result, nil
}

func removeSpool(f *os.File) {
	if f == nil {
		return
	}
	f.Close()
	os.Remove(f.Name())
}

// spooledInner wraps a temporary file holding a fully verified envelope.
type spooledInner struct {
	*os.File
}

func (s *spooledInner) Close() error {
	name := s.File.Name()
	err := s.File.Close()
	os.Remove(name)
	return err
}
