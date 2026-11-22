// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package provenance

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// ageIntro is the binary age header intro. Signing refuses anything that
// does not begin with it (armored input must be de-armored by the caller
// first, so both armored and binary age files end up hashed identically).
var ageIntro = []byte("age-encryption.org/v1\n")

// SignParams configures a signing operation.
type SignParams struct {
	// SecretKeys are the Ed25519 private keys to sign with. At least one is
	// required.
	SecretKeys []ed25519.PrivateKey
	// Created is the signing time recorded inside every signature.
	Created time.Time
	// Expires optionally limits the lifetime of the produced proof.
	Expires time.Time
	// TempDir is used to spool non-seekable inputs (e.g. stdin). It
	// defaults to the operating system temp directory.
	TempDir string
}

// Sign reads an age ciphertext from inner and writes a complete
// age-proof-v1 envelope to dst. The inner bytes are copied verbatim: the
// age file itself is never re-encoded.
//
// Memory is bounded regardless of input size. A non-seekable input is
// spooled to a 0600 temporary file, which is removed before Sign returns.
func Sign(dst io.Writer, inner io.Reader, p SignParams) error {
	if len(p.SecretKeys) == 0 {
		return errors.New("provenance: no signing keys provided")
	}
	created := p.Created.UTC()
	if created.IsZero() {
		created = time.Now().UTC()
	}
	var expires int64
	if !p.Expires.IsZero() {
		exp := p.Expires.UTC()
		if !exp.After(created) {
			return errors.New("provenance: expiration must be after creation time")
		}
		expires = exp.Unix()
	}
	for _, k := range p.SecretKeys {
		if len(k) != ed25519.PrivateKeySize {
			return errors.New("provenance: invalid Ed25519 private key")
		}
	}

	// Hash the inner payload and make it re-readable without holding it in
	// memory. Every consumed byte, including the intro, reaches hash.
	hash := sha256.New()
	var reread io.Reader
	var size int64

	if seeker, ok := inner.(io.Seeker); ok {
		start, err := seeker.Seek(0, io.SeekCurrent)
		if err != nil {
			return fmt.Errorf("provenance: failed to reposition input: %w", err)
		}
		head, err := readAgeIntro(inner)
		if err != nil {
			return err
		}
		hash.Write(head)
		n, err := io.CopyBuffer(hash, inner, make([]byte, copyBufferSize))
		if err != nil {
			return fmt.Errorf("provenance: failed to read input: %w", err)
		}
		size = int64(len(head)) + n
		if _, err := seeker.Seek(start, io.SeekStart); err != nil {
			return fmt.Errorf("provenance: failed to rewind input: %w", err)
		}
		reread = inner
	} else {
		spool, err := os.CreateTemp(p.TempDir, "age-proof-spool-*")
		if err != nil {
			return fmt.Errorf("provenance: failed to create temporary file: %w", err)
		}
		spoolName := spool.Name()
		defer os.Remove(spoolName)
		if err := spool.Chmod(0600); err != nil {
			spool.Close()
			return fmt.Errorf("provenance: failed to secure temporary file: %w", err)
		}
		sink := io.MultiWriter(hash, spool)
		head, err := readAgeIntro(io.TeeReader(inner, sink))
		if err != nil {
			spool.Close()
			return err
		}
		// The TeeReader above already mirrored the intro into hash and
		// spool; stream the remainder into the same two sinks.
		n, err := io.CopyBuffer(sink, inner, make([]byte, copyBufferSize))
		if err != nil {
			spool.Close()
			return fmt.Errorf("provenance: failed to read input: %w", err)
		}
		size = int64(len(head)) + n
		if _, err := spool.Seek(0, io.SeekStart); err != nil {
			spool.Close()
			return fmt.Errorf("provenance: failed to rewind temporary file: %w", err)
		}
		reread = spool
		defer spool.Close()
	}

	digest := hash.Sum(nil)

	signers := make([]*Signer, 0, len(p.SecretKeys))
	for _, priv := range p.SecretKeys {
		pub := priv.Public().(ed25519.PublicKey)
		keyID := sha256.Sum256(pub)
		msg := signedMessage(size, digest, keyID[:], created.Unix(), expires)
		sig := ed25519.Sign(priv, msg)
		s := &Signer{
			PublicKey: pub,
			KeyID:     keyID[:],
			Signature: sig,
			Created:   created,
		}
		if expires != 0 {
			s.Expires = time.Unix(expires, 0).UTC()
		}
		signers = append(signers, s)
	}

	if err := marshalHeader(dst, signers, size, digest); err != nil {
		return fmt.Errorf("provenance: failed to write proof header: %w", err)
	}
	n, err := io.CopyBuffer(dst, reread, make([]byte, copyBufferSize))
	if err != nil {
		return fmt.Errorf("provenance: failed to write inner ciphertext: %w", err)
	}
	if n != size {
		return fmt.Errorf("%w: input size changed while signing", ErrProofInvalid)
	}
	return nil
}

// readAgeIntro reads and returns the binary age header intro from r,
// rejecting anything that is not an age ciphertext.
func readAgeIntro(r io.Reader) ([]byte, error) {
	head := make([]byte, len(ageIntro))
	if _, err := io.ReadFull(r, head); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return nil, ErrNotEncrypted
		}
		return nil, fmt.Errorf("provenance: failed to read input: %w", err)
	}
	if !bytes.Equal(head, ageIntro) {
		return nil, ErrNotEncrypted
	}
	return head, nil
}
