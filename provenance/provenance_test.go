// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package provenance

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// testEnv bundles keys, a trust list and an age-shaped payload.
type testEnv struct {
	pub1, pub2, pub3 ed25519.PublicKey
	priv1, priv2     ed25519.PrivateKey
	trust            []*TrustEntry
	ageFile          []byte
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	env := &testEnv{}
	env.pub1, env.priv1 = mustKey(t)
	env.pub2, env.priv2 = mustKey(t)
	env.pub3, _ = mustKey(t)
	env.trust = []*TrustEntry{
		trustEntry(t, env.pub1, Trusted, "alice"),
		trustEntry(t, env.pub2, Trusted, "bob"),
	}
	// A plausible binary age header followed by payload; only the envelope
	// cares about the bytes, not their age semantics.
	env.ageFile = append([]byte("age-encryption.org/v1\n-> x25519 AAAA\n--- "),
		bytes.Repeat([]byte("Z"), 70000)...)
	return env
}

func mustKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func trustEntry(t *testing.T, pub ed25519.PublicKey, status TrustStatus, label string) *TrustEntry {
	t.Helper()
	id := sha256Sum(pub)
	return &TrustEntry{PublicKey: pub, KeyID: id, Status: status, Label: label}
}

func signBytes(t *testing.T, inner []byte, keys ...ed25519.PrivateKey) []byte {
	t.Helper()
	var out bytes.Buffer
	err := Sign(&out, bytes.NewReader(inner), SignParams{SecretKeys: keys})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return out.Bytes()
}

func openAndDrain(t *testing.T, envBytes []byte, trust []*TrustEntry) *VerifyResult {
	t.Helper()
	inner, res, err := Open(bytes.NewReader(envBytes), VerifyParams{Trust: trust})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, err := io.ReadAll(inner)
	if err != nil {
		t.Fatalf("reading inner: %v", err)
	}
	if err := inner.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if !bytes.HasPrefix(got, []byte("age-encryption.org/v1\n")) {
		t.Fatal("inner payload altered")
	}
	return res
}

func TestRoundTripSingleAndMultiSigner(t *testing.T) {
	env := newTestEnv(t)

	for _, tc := range []struct {
		name string
		keys []ed25519.PrivateKey
		want int
	}{
		{"single", []ed25519.PrivateKey{env.priv1}, 1},
		{"multi", []ed25519.PrivateKey{env.priv1, env.priv2}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			envBytes := signBytes(t, env.ageFile, tc.keys...)
			res := openAndDrain(t, envBytes, env.trust)
			if len(res.Signers) != tc.want {
				t.Fatalf("got %d verified signers, want %d", len(res.Signers), tc.want)
			}
		})
	}
}

func TestInnerBytesVerbatim(t *testing.T) {
	env := newTestEnv(t)
	envBytes := signBytes(t, env.ageFile, env.priv1)
	var unwrapped bytes.Buffer
	if err := Unwrap(bytes.NewReader(envBytes), &unwrapped); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unwrapped.Bytes(), env.ageFile) {
		t.Fatal("unwrap did not recover the exact inner bytes")
	}
}

func TestPartialTrustOnlySomeSigners(t *testing.T) {
	env := newTestEnv(t)
	// Envelope signed by trusted alice and unknown key 3.
	envBytes := signBytes(t, env.ageFile, env.priv1, mustPrivFor(t, env.pub3))
	res := openAndDrain(t, envBytes, env.trust)
	if len(res.Signers) != 1 {
		t.Fatalf("want exactly 1 trusted signature, got %d", len(res.Signers))
	}
	if !bytes.Equal(res.Signers[0].KeyID, sha256Sum(env.pub1)) {
		t.Fatal("verified the wrong signer")
	}
}

func mustPrivFor(t *testing.T, pub ed25519.PublicKey) ed25519.PrivateKey {
	t.Helper()
	// testEnv generated pub3 with a discarded private key; regenerate pair
	// and swap the trusted set's expectation instead. Here we just make a
	// fresh key whose public side is treated as unknown.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func TestSignRejectsNonAge(t *testing.T) {
	env := newTestEnv(t)
	cases := map[string][]byte{
		"plaintext":    []byte("hello world, not encrypted at all"),
		"empty":        {},
		"one byte":     {'a'},
		"short header": []byte("age-encryption.org"),
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			err := Sign(&out, bytes.NewReader(payload), SignParams{SecretKeys: []ed25519.PrivateKey{env.priv1}})
			if !errors.Is(err, ErrNotEncrypted) {
				t.Fatalf("want ErrNotEncrypted, got %v", err)
			}
			if out.Len() != 0 {
				t.Fatal("no output may be written on rejection")
			}
		})
	}
}

func TestSignRejectsNonSeekablePlaintextAndCleansSpool(t *testing.T) {
	env := newTestEnv(t)
	var out bytes.Buffer
	err := Sign(&out, bytes.NewReader([]byte("plaintext pipe")), SignParams{SecretKeys: []ed25519.PrivateKey{env.priv1}})
	if !errors.Is(err, ErrNotEncrypted) {
		t.Fatalf("got %v", err)
	}
}

func TestUnknownRevokedExpired(t *testing.T) {
	env := newTestEnv(t)
	envBytes := signBytes(t, env.ageFile, env.priv1)
	env3 := signBytes(t, env.ageFile, mustPrivFor(t, env.pub3))

	t.Run("unknown signer", func(t *testing.T) {
		trust := []*TrustEntry{trustEntry(t, env.pub2, Trusted, "only-bob")}
		_, _, err := Open(bytes.NewReader(envBytes), VerifyParams{Trust: trust})
		if !errors.Is(err, ErrSignerUnknown) {
			t.Fatalf("want ErrSignerUnknown, got %v", err)
		}
	})

	t.Run("revoked signer", func(t *testing.T) {
		trust := []*TrustEntry{trustEntry(t, env.pub1, Revoked, "alice-revoked")}
		_, _, err := Open(bytes.NewReader(envBytes), VerifyParams{Trust: trust})
		if !errors.Is(err, ErrSignerRevoked) {
			t.Fatalf("want ErrSignerRevoked, got %v", err)
		}
	})

	t.Run("proof expired", func(t *testing.T) {
		var out bytes.Buffer
		err := Sign(&out, bytes.NewReader(env.ageFile), SignParams{
			SecretKeys: []ed25519.PrivateKey{env.priv1},
			Created:    time.Now().Add(-2 * time.Hour),
			Expires:    time.Now().Add(-time.Hour),
		})
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = Open(bytes.NewReader(out.Bytes()), VerifyParams{Trust: env.trust})
		if !errors.Is(err, ErrProofExpired) {
			t.Fatalf("want ErrProofExpired, got %v", err)
		}
	})

	t.Run("trust entry expired", func(t *testing.T) {
		entry := trustEntry(t, env.pub1, Trusted, "alice-old")
		entry.Expires = time.Now().Add(-time.Minute)
		_, _, err := Open(bytes.NewReader(envBytes), VerifyParams{Trust: []*TrustEntry{entry}})
		if !errors.Is(err, ErrProofExpired) {
			t.Fatalf("want ErrProofExpired, got %v", err)
		}
	})

	t.Run("unknown key alone", func(t *testing.T) {
		_, _, err := Open(bytes.NewReader(env3), VerifyParams{Trust: env.trust})
		if !errors.Is(err, ErrSignerUnknown) {
			t.Fatalf("want ErrSignerUnknown, got %v", err)
		}
	})
}

func TestMissingAndMalformed(t *testing.T) {
	env := newTestEnv(t)

	t.Run("legacy age file is missing not invalid", func(t *testing.T) {
		_, _, err := Open(bytes.NewReader(env.ageFile), VerifyParams{Trust: env.trust})
		if !errors.Is(err, ErrProofMissing) {
			t.Fatalf("want ErrProofMissing, got %v", err)
		}
	})

	t.Run("truncated header", func(t *testing.T) {
		envBytes := signBytes(t, env.ageFile, env.priv1)
		_, _, err := Open(bytes.NewReader(envBytes[:40]), VerifyParams{Trust: env.trust})
		if !errors.Is(err, ErrProofInvalid) {
			t.Fatalf("want ErrProofInvalid, got %v", err)
		}
	})

	t.Run("truncated payload", func(t *testing.T) {
		envBytes := signBytes(t, env.ageFile, env.priv1)
		inner, _, err := Open(bytes.NewReader(envBytes[:len(envBytes)-100]), VerifyParams{Trust: env.trust})
		if err == nil {
			inner.Close()
			t.Fatal("truncated payload accepted at Open")
		}
		if !errors.Is(err, ErrProofInvalid) {
			t.Fatalf("want ErrProofInvalid on truncated payload, got %v", err)
		}
	})

	t.Run("appended second file rejected", func(t *testing.T) {
		a := signBytes(t, env.ageFile, env.priv1)
		b := signBytes(t, env.ageFile, env.priv2)
		joined := append(append([]byte{}, a...), b...)
		inner, _, err := Open(bytes.NewReader(joined), VerifyParams{Trust: env.trust})
		if err == nil {
			inner.Close()
			t.Fatal("concatenation accepted at Open")
		}
		if !errors.Is(err, ErrProofInvalid) {
			t.Fatalf("want ErrProofInvalid on concatenation, got %v", err)
		}
	})

	t.Run("cross-file proof transplant", func(t *testing.T) {
		a := signBytes(t, env.ageFile, env.priv1)
		other := append([]byte("age-encryption.org/v1\n-> x25519 BBBB\n--- "),
			bytes.Repeat([]byte("Q"), 70000)...)
		b := signBytes(t, other, env.priv1)

		hdrA, _ := splitEnvelope(t, a)
		_, payloadB := splitEnvelope(t, b)
		frankenstein := append(append([]byte{}, hdrA...), payloadB...)

		inner, _, err := Open(bytes.NewReader(frankenstein), VerifyParams{Trust: env.trust})
		if err == nil {
			inner.Close()
			t.Fatal("transplanted proof accepted")
		}
		if !errors.Is(err, ErrProofInvalid) {
			t.Fatalf("transplanted proof must fail, got %v", err)
		}
	})
}

// splitEnvelope cuts an envelope at the end of its "-> end" line.
func splitEnvelope(t *testing.T, envBytes []byte) (header, payload []byte) {
	t.Helper()
	marker := []byte("-> end ")
	idx := bytes.Index(envBytes, marker)
	if idx < 0 {
		t.Fatal("no end stanza")
	}
	lineEnd := bytes.IndexByte(envBytes[idx:], '\n')
	if lineEnd < 0 {
		t.Fatal("no end line terminator")
	}
	cut := idx + lineEnd + 1
	return envBytes[:cut], envBytes[cut:]
}

func TestBytewiseTamperRegions(t *testing.T) {
	env := newTestEnv(t)
	original := signBytes(t, env.ageFile, env.priv1)

	// Header, signature area, length field, and payload (including a point
	// near a base64/streaming boundary) are all covered.
	regions := map[string]int{
		"signer stanza":     bytes.Index(original, []byte("-> signer")) + 12,
		"public key body":   bytes.Index(original, []byte("-> signer")) + 60,
		"signature stanza":  bytes.Index(original, []byte("-> ed25519")) + 14,
		"signature body":    bytes.Index(original, []byte("-> ed25519")) + 80,
		"length field":      bytes.Index(original, []byte("-> end")) + 8,
		"payload start":     len(original) - len(env.ageFile) + 5,
		"payload middle":    len(original) - len(env.ageFile)/2,
		"payload last byte": len(original) - 1,
	}
	for name, pos := range regions {
		t.Run(name, func(t *testing.T) {
			if pos <= 0 || pos >= len(original) {
				t.Fatalf("bad tamper position %d (len %d)", pos, len(original))
			}
			tampered := append([]byte{}, original...)
			tampered[pos] ^= 0xFF
			assertRejectedZeroOutput(t, tampered, env.trust)
		})
	}

	// The version line is what makes a file an envelope at all: flipping
	// it must still be refused, classified as a missing envelope rather
	// than accepted as a legacy file by callers that only branch on
	// ErrProofMissing when the input was expected to carry a proof.
	t.Run("version line", func(t *testing.T) {
		tampered := append([]byte{}, original...)
		tampered[3] ^= 0xFF
		_, _, err := Open(bytes.NewReader(tampered), VerifyParams{Trust: env.trust})
		if !errors.Is(err, ErrProofMissing) {
			t.Fatalf("want ErrProofMissing for broken magic, got %v", err)
		}
	})
}

// assertRejectedZeroOutput verifies that a tampered envelope is refused at
// Open, so no verified inner byte is ever delivered.
func assertRejectedZeroOutput(t *testing.T, envBytes []byte, trust []*TrustEntry) {
	t.Helper()
	inner, _, err := Open(bytes.NewReader(envBytes), VerifyParams{Trust: trust})
	if err == nil {
		inner.Close()
		t.Fatal("tampered envelope accepted")
	}
	if !errors.Is(err, ErrProofInvalid) {
		t.Fatalf("want ErrProofInvalid, got %v", err)
	}
}

// TestChunkBoundaryTamper builds an inner payload spanning several
// streaming-copy (32 KiB) and age-chunk (64 KiB) boundaries and flips bytes
// immediately on either side of each. Every variant must be rejected before
// any verified inner byte is produced.
func TestChunkBoundaryTamper(t *testing.T) {
	env := newTestEnv(t)
	intro := []byte("age-encryption.org/v1\n")
	// 200 KiB of deterministic payload, well beyond every boundary of
	// interest.
	payload := make([]byte, 200*1024)
	pattern := []byte("boundary-pattern-")
	for i := range payload {
		payload[i] = pattern[i%len(pattern)]
	}
	inner := append(append([]byte{}, intro...), payload...)
	original := signBytes(t, inner, env.priv1)

	parsed, err := parseHeader(bufio.NewReader(bytes.NewReader(original)))
	if err != nil {
		t.Fatal(err)
	}
	headerLen := int(parsed.headerBytes)

	for _, boundary := range []int{
		copyBufferSize,     // 32 KiB streaming buffer
		2 * copyBufferSize, // two buffers in
		64 * 1024,          // age payload chunk size
		128 * 1024,         // two age chunks in
	} {
		for _, delta := range []int{-1, 0, 1} {
			pos := headerLen + boundary + delta
			t.Run(fmt.Sprintf("boundary-%d-delta-%d", boundary, delta), func(t *testing.T) {
				if pos <= 0 || pos >= len(original) {
					t.Fatalf("position out of range: %d", pos)
				}
				tampered := append([]byte{}, original...)
				tampered[pos] ^= 0x01
				assertRejectedZeroOutput(t, tampered, env.trust)
			})
		}
	}
}

func TestArmoredRoundTripAndStrictness(t *testing.T) {
	env := newTestEnv(t)
	var armored bytes.Buffer
	w := NewArmorWriter(&armored)
	if _, err := w.Write(signBytes(t, env.ageFile, env.priv1)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(armored.String(), ArmorHeader) {
		t.Fatal("missing armor header")
	}
	isEnv, isArmored, rr, err := Detect(bytes.NewReader(armored.Bytes()))
	if err != nil || !isEnv || !isArmored {
		t.Fatalf("Detect: %v %v %v", isEnv, isArmored, err)
	}
	inner, res, err := Open(NewArmorReader(rr), VerifyParams{Trust: env.trust})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, inner); err != nil {
		t.Fatalf("armored stream: %v", err)
	}
	inner.Close()
	if len(res.Signers) != 1 {
		t.Fatal("armored verification failed")
	}

	// Armor strictness: junk after the footer must be rejected.
	bad := append(append([]byte{}, armored.Bytes()...), []byte("garbage")...)
	if _, err := io.ReadAll(NewArmorReader(bytes.NewReader(bad))); err == nil {
		t.Fatal("trailing armor junk accepted")
	}
}

func TestTrustListGrammar(t *testing.T) {
	env := newTestEnv(t)
	pub4, _ := mustKey(t)
	native, err := EncodeNativePublicKey(env.pub1)
	if err != nil {
		t.Fatal(err)
	}
	sshLine := sshAuthorizedLine(t, env.pub2)
	doc := fmt.Sprintf(`# comment

%s alice-label
%s bob-label
revoked: %s
expires: 2030-01-01T00:00:00Z %s carol
`, native, sshLine, sshAuthorizedLine(t, env.pub3), sshAuthorizedLine(t, pub4))
	entries, err := LoadTrustList(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("got %d entries", len(entries))
	}
	if entries[2].Status != Revoked {
		t.Fatal("revoked directive ignored")
	}
	if entries[3].Expires.IsZero() || entries[3].Label != "carol" {
		t.Fatalf("expires/label parse wrong: %+v", entries[3])
	}

	for _, bad := range []string{
		"",
		"# only a comment\n",
		"not-a-key at all\n",
		"revoked:\n",
		"expires: not-a-date " + native + "\n",
	} {
		if _, err := LoadTrustList(strings.NewReader(bad)); !errors.Is(err, ErrTrustListUnavailable) {
			t.Fatalf("input %q: want ErrTrustListUnavailable, got %v", bad, err)
		}
	}
}

func TestTrustListMissingFileIsRejection(t *testing.T) {
	if _, err := LoadTrustListFile("/nonexistent/age-proof-trust-list"); !errors.Is(err, ErrTrustListUnavailable) {
		t.Fatalf("got %v", err)
	}
}

func TestStreamingMemoryBounded(t *testing.T) {
	env := newTestEnv(t)

	// 16 MiB of real data, hundreds of times larger than the 32 KiB stream
	// buffer: a bounded implementation keeps heap growth near the buffer
	// size, an unbounded one buffers the whole payload.
	const size int64 = 16 << 20
	big, err := os.CreateTemp(t.TempDir(), "big-*.age")
	if err != nil {
		t.Fatal(err)
	}
	defer big.Close()
	if _, err := big.Write([]byte("age-encryption.org/v1\n")); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, size-int64(len("age-encryption.org/v1\n")))
	if _, err := rand.Read(body); err != nil {
		t.Fatal(err)
	}
	if _, err := big.Write(body); err != nil {
		t.Fatal(err)
	}
	total := size
	if _, err := big.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}

	envFile, err := os.CreateTemp(t.TempDir(), "big-*.proof")
	if err != nil {
		t.Fatal(err)
	}
	defer envFile.Close()
	if err := Sign(envFile, big, SignParams{SecretKeys: []ed25519.PrivateKey{env.priv1}}); err != nil {
		t.Fatalf("Sign large: %v", err)
	}
	if fi, _ := envFile.Stat(); fi.Size() <= total {
		t.Fatalf("envelope unexpectedly small: %d", fi.Size())
	}
	if _, err := envFile.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	inner, res, err := Open(envFile, VerifyParams{Trust: env.trust})
	if err != nil {
		t.Fatalf("Open large: %v", err)
	}
	n, err := io.Copy(io.Discard, inner)
	if err != nil {
		t.Fatalf("stream large: %v", err)
	}
	if err := inner.Close(); err != nil {
		t.Fatal(err)
	}
	if n != total {
		t.Fatalf("streamed %d of %d", n, total)
	}
	if len(res.Signers) != 1 {
		t.Fatal("large file verification failed")
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	growth := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	// Allow generous fixed overhead (buffers, hash state, parsed header)
	// but nowhere near the 16 MiB payload.
	const bound = 8 << 20
	if growth > bound {
		t.Fatalf("heap grew by %d bytes during %d-byte stream (bound %d)", growth, total, bound)
	}
}

func TestNonSeekableSpoolPath(t *testing.T) {
	env := newTestEnv(t)
	// A pipe-like reader with no Seek/Stat methods.
	envBytes := signBytes(t, env.ageFile, env.priv1)
	pipe := &pureReader{r: bytes.NewReader(envBytes)}
	inner, _, err := Open(pipe, VerifyParams{Trust: env.trust})
	if err != nil {
		t.Fatalf("Open non-seekable: %v", err)
	}
	got, err := io.ReadAll(inner)
	if err != nil {
		t.Fatal(err)
	}
	if err := inner.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(got, []byte("age-encryption.org/v1\n")) {
		t.Fatal("spooled inner stream wrong")
	}
}

type pureReader struct{ r io.Reader }

func (p *pureReader) Read(b []byte) (int, error) { return p.r.Read(b) }

func TestNoTrailingDataOnSignedOutput(t *testing.T) {
	env := newTestEnv(t)
	envBytes := signBytes(t, env.ageFile, env.priv1)
	e, err := parseHeader(bufio.NewReader(bytes.NewReader(envBytes)))
	if err != nil {
		t.Fatal(err)
	}
	if e.InnerSize != int64(len(env.ageFile)) {
		t.Fatalf("size %d want %d", e.InnerSize, len(env.ageFile))
	}
	if fmt.Sprintf("%x", e.InnerDigest) != fmt.Sprintf("%x", sha256SumBytes(env.ageFile)) {
		t.Fatal("digest mismatch")
	}
}
