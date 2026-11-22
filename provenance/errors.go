// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package provenance implements the age-proof-v1 accountable provenance
// layer: an outer, stream-verifiable envelope of Ed25519 signatures around
// an unmodified age ciphertext.
//
// The envelope never alters the inner age file: it sits entirely outside
// it, and [Envelope.Open] hands back the exact inner byte stream. Readers
// that don't understand the layer can recover the inner file with the
// age-proof "unwrap" command and decrypt it with an unmodified age build.
package provenance

import "errors"

// Sentinel errors. Callers should use errors.Is to distinguish the failure
// classes; the wrapped messages never contain key material, passphrases or
// plaintext.
var (
	// ErrProofMissing is returned when the input is not an age-proof-v1
	// envelope at all (so a legacy file can be routed to plain age).
	ErrProofMissing = errors.New("provenance: no proof envelope")

	// ErrProofInvalid covers a malformed envelope, a signature that fails
	// cryptographic verification, an inner digest or length mismatch,
	// truncation, appended data, and a proof transplanted onto another
	// file.
	ErrProofInvalid = errors.New("provenance: proof is invalid or corrupted")

	// ErrSignerUnknown means every signature was made by a key that is not
	// in the receiver's trust list.
	ErrSignerUnknown = errors.New("provenance: signer is not in the trust list")

	// ErrSignerRevoked means a signature was made by a key explicitly
	// marked revoked in the trust list.
	ErrSignerRevoked = errors.New("provenance: signer has been revoked")

	// ErrProofExpired means the proof (or the trust entry for its signer)
	// is past its expiration time.
	ErrProofExpired = errors.New("provenance: proof has expired")

	// ErrTrustListUnavailable means the trust list could not be read, is
	// empty, or contains no usable entries. Verification never degrades to
	// acceptance.
	ErrTrustListUnavailable = errors.New("provenance: trust list is unavailable")

	// ErrNotEncrypted means the input offered for signing does not look
	// like an age ciphertext. Signing plaintext is refused outright.
	ErrNotEncrypted = errors.New("provenance: input is not an age encrypted file")
)
