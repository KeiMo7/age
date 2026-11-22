// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package provenance

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"filippo.io/age/internal/bech32"
	"golang.org/x/crypto/ssh"
)

// NativePublicKeyHRP is the human-readable prefix of the native provenance
// public key encoding: age-proof-1 followed by bech32 of the raw 32-byte
// Ed25519 key.
const NativePublicKeyHRP = "age-proof-1"

// EncodeNativePublicKey returns the bech32 text form of a signer public key.
func EncodeNativePublicKey(pub ed25519.PublicKey) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", errors.New("provenance: invalid Ed25519 public key")
	}
	return bech32.Encode(NativePublicKeyHRP, pub)
}

// ParseNativePublicKey decodes the bech32 text form of a signer public key.
func ParseNativePublicKey(s string) (ed25519.PublicKey, error) {
	hrp, data, err := bech32.Decode(s)
	if err != nil || hrp != NativePublicKeyHRP || len(data) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("provenance: malformed %s public key", NativePublicKeyHRP)
	}
	return ed25519.PublicKey(data), nil
}

// ParseSignerPublicKey accepts either an OpenSSH authorized_keys line
// ("ssh-ed25519 AAAA... [label]") or a native age-proof-1 key (in which
// case label is ignored).
func ParseSignerPublicKey(s string, label string) (ed25519.PublicKey, error) {
	switch {
	case strings.HasPrefix(s, NativePublicKeyHRP):
		pub, err := ParseNativePublicKey(s)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrTrustListUnavailable, err)
		}
		return pub, nil
	case strings.HasPrefix(s, "ssh-ed25519 "):
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(s)))
		if err != nil {
			return nil, fmt.Errorf("%w: malformed SSH public key: %v", ErrTrustListUnavailable, err)
		}
		cryptoKey, ok := key.(ssh.CryptoPublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: unsupported SSH key type", ErrTrustListUnavailable)
		}
		pub, ok := cryptoKey.CryptoPublicKey().(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: only ssh-ed25519 keys are supported", ErrTrustListUnavailable)
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("%w: unrecognized public key format", ErrTrustListUnavailable)
	}
}

// ParseSignerPrivateKey reads an Ed25519 private key. Supported forms are
// OpenSSH PEM (BEGIN OPENSSH PRIVATE KEY, including passphrase-protected
// keys handled by the caller's prompt) and PKCS#8 PEM containing an
// Ed25519 key. Parse errors are reported without echoing the material.
func ParseSignerPrivateKey(pem []byte) (ed25519.PrivateKey, error) {
	key, err := ssh.ParseRawPrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("provenance: failed to parse signer key: %w", sanitizeKeyError(err))
	}
	switch k := key.(type) {
	case ed25519.PrivateKey:
		return k, nil
	case *ed25519.PrivateKey:
		return *k, nil
	default:
		return nil, fmt.Errorf("provenance: signer key is not Ed25519 (got %T)", key)
	}
}

// sanitizeKeyError makes sure a key parse failure never carries key
// contents into a message. ssh errors are typed and contain no key bytes,
// but normalize anyway.
func sanitizeKeyError(err error) error {
	var pme *ssh.PassphraseMissingError
	if errors.As(err, &pme) {
		return errors.New("signer key is passphrase-protected; decrypt it first or use an unencrypted key")
	}
	return errors.New("malformed or unsupported private key")
}

// GenerateSignerKey creates a fresh Ed25519 key pair.
func GenerateSignerKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(nil)
}

// KeyFingerprint returns the lowercase hex SHA-256 fingerprint of a signer
// public key.
func KeyFingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return fmt.Sprintf("%x", sum[:])
}
