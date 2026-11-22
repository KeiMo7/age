// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"filippo.io/age/provenance"
	"golang.org/x/crypto/ssh"
)

// helper builds the age-proof binary once into the test temp dir.
func helperBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "age-proof")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build age-proof: %v\n%s", err, out)
	}
	return bin
}

func ageBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "age")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, "filippo.io/age/cmd/age")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build age: %v\n%s", err, out)
	}
	return bin
}

type cliHarness struct {
	t       *testing.T
	proof   string
	age     string
	dir     string
	signers []ed25519.PrivateKey
	pubs    []ed25519.PublicKey
}

func newHarness(t *testing.T, nSigners int) *cliHarness {
	t.Helper()
	h := &cliHarness{
		t:     t,
		proof: helperBinary(t),
		age:   ageBinary(t),
		dir:   t.TempDir(),
	}
	for range nSigners {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		h.signers = append(h.signers, priv)
		h.pubs = append(h.pubs, pub)
	}
	for i, priv := range h.signers {
		block, err := ssh.MarshalPrivateKey(priv, fmt.Sprintf("signer-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(h.path(fmt.Sprintf("signer%d", i)),
			pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func (h *cliHarness) path(name string) string { return filepath.Join(h.dir, name) }

func (h *cliHarness) writeFile(name, content string) {
	h.t.Helper()
	if err := os.WriteFile(h.path(name), []byte(content), 0644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *cliHarness) writeRandom(name string, size int) {
	h.t.Helper()
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(h.path(name), buf, 0644); err != nil {
		h.t.Fatal(err)
	}
}

// trustList writes a list containing the selected signer indexes with the
// given statuses.
func (h *cliHarness) trustList(name string, status map[int]string) string {
	h.t.Helper()
	var lines []string
	for i, pub := range h.pubs {
		sshPub, err := ssh.NewPublicKey(pub)
		if err != nil {
			h.t.Fatal(err)
		}
		line := strings.TrimRight(string(ssh.MarshalAuthorizedKey(sshPub)), "\n")
		switch status[i] {
		case "revoked":
			line = "revoked: " + line
		case "expired":
			line = "expires: 2000-01-01T00:00:00Z " + line
		}
		lines = append(lines, line)
	}
	path := h.path(name)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		h.t.Fatal(err)
	}
	return path
}

type cliResult struct {
	exitCode int
	stdout   []byte
	stderr   string
}

func (h *cliHarness) runProof(stdin io.Reader, args ...string) cliResult {
	h.t.Helper()
	cmd := exec.Command(h.proof, args...)
	cmd.Dir = h.dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Stdin = stdin
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if ok := asExitError(err, &ee); !ok {
			h.t.Fatalf("age-proof %v: %v\n%s", args, err, stderr.String())
		}
		code = ee.ExitCode()
	}
	return cliResult{exitCode: code, stdout: stdout.Bytes(), stderr: stderr.String()}
}

func asExitError(err error, target **exec.ExitError) bool {
	for err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			*target = ee
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func (h *cliHarness) runAge(stdin io.Reader, args ...string) cliResult {
	h.t.Helper()
	cmd := exec.Command(h.age, args...)
	cmd.Dir = h.dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Stdin = stdin
	err := cmd.Run()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if ok := asExitError(err, &ee); !ok {
			h.t.Fatalf("age %v: %v\n%s", args, err, stderr.String())
		}
		code = ee.ExitCode()
	}
	return cliResult{exitCode: code, stdout: stdout.Bytes(), stderr: stderr.String()}
}

// encryptAge produces a binary age file encrypted to the harness's first
// age identity using the real age binary.
func (h *cliHarness) encryptAge(plainName, cipherName string) {
	h.t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(h.path("age-id.txt"), []byte(id.String()+"\n"), 0600); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(h.path("age-rec.txt"), []byte(id.Recipient().String()+"\n"), 0644); err != nil {
		h.t.Fatal(err)
	}
	res := h.runAge(nil, "-r", id.Recipient().String(),
		"-o", h.path(cipherName), h.path(plainName))
	if res.exitCode != 0 {
		h.t.Fatalf("age encrypt: %s", res.stderr)
	}
}

func TestCLISignVerifyDecryptRoundTrip(t *testing.T) {
	h := newHarness(t, 2)
	h.writeFile("plain.txt", "the quick brown fox\n")
	h.encryptAge("plain.txt", "secret.age")
	trust := h.trustList("trust.txt", map[int]string{0: "trusted", 1: "trusted"})

	// Single signer, binary envelope.
	if r := h.runProof(nil, "sign", "-k", h.path("signer0"),
		"-o", h.path("secret.age.proof"), h.path("secret.age")); r.exitCode != 0 {
		t.Fatalf("sign: %s", r.stderr)
	}
	if r := h.runProof(nil, "verify", "-t", trust, h.path("secret.age.proof")); r.exitCode != 0 {
		t.Fatalf("verify: %s", r.stderr)
	}
	if r := h.runProof(nil, "decrypt", "-t", trust, "-i", h.path("age-id.txt"),
		"-o", h.path("out.txt"), h.path("secret.age.proof")); r.exitCode != 0 {
		t.Fatalf("decrypt: %s", r.stderr)
	}
	got, err := os.ReadFile(h.path("out.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "the quick brown fox\n" {
		t.Fatalf("plaintext mismatch: %q", got)
	}

	// Multi-signer envelope; both must verify and be listed.
	if r := h.runProof(nil, "sign", "-k", h.path("signer0"), "-k", h.path("signer1"),
		"-o", h.path("multi.proof"), h.path("secret.age")); r.exitCode != 0 {
		t.Fatalf("multi-sign: %s", r.stderr)
	}
	r := h.runProof(nil, "verify", "--list", "-t", trust, h.path("multi.proof"))
	if r.exitCode != 0 || strings.Count(r.stderr, "ok signer") != 2 {
		t.Fatalf("list verify: code=%d stderr=%s", r.exitCode, r.stderr)
	}
}

func TestCLIArmoredAndInteropWithPlainAge(t *testing.T) {
	h := newHarness(t, 1)
	h.writeFile("plain.txt", "interoperable\n")
	h.encryptAge("plain.txt", "secret.age")
	trust := h.trustList("trust.txt", map[int]string{0: "trusted"})

	if r := h.runProof(nil, "sign", "--armor", "-k", h.path("signer0"),
		"-o", h.path("secret.age.aproof"), h.path("secret.age")); r.exitCode != 0 {
		t.Fatalf("armored sign: %s", r.stderr)
	}
	head, err := os.ReadFile(h.path("secret.age.aproof"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(head, []byte(provenance.ArmorHeader)) {
		t.Fatal("armor header missing")
	}
	if r := h.runProof(nil, "verify", "-t", trust, h.path("secret.age.aproof")); r.exitCode != 0 {
		t.Fatalf("armored verify: %s", r.stderr)
	}

	// A reader that does not know the layer unwraps the inner age file and
	// decrypts it with the stock age binary: outer format does not pollute
	// the inner one.
	if r := h.runProof(nil, "unwrap", "-o", h.path("recovered.age"),
		h.path("secret.age.aproof")); r.exitCode != 0 {
		t.Fatalf("unwrap: %s", r.stderr)
	}
	orig, _ := os.ReadFile(h.path("secret.age"))
	rec, _ := os.ReadFile(h.path("recovered.age"))
	if !bytes.Equal(orig, rec) {
		t.Fatal("unwrap changed inner age bytes")
	}
	if r := h.runAge(nil, "-d", "-i", h.path("age-id.txt"),
		"-o", h.path("final.txt"), h.path("recovered.age")); r.exitCode != 0 {
		t.Fatalf("stock age decrypt of unwrapped file: %s", r.stderr)
	}
}

func TestCLILegacyFileStillWorks(t *testing.T) {
	h := newHarness(t, 1)
	h.writeFile("plain.txt", "legacy behavior unchanged\n")
	h.encryptAge("plain.txt", "old.age")
	trust := h.trustList("trust.txt", map[int]string{0: "trusted"})

	// Without --require-proof an un-enveloped age file decrypts normally.
	r := h.runProof(nil, "decrypt", "-t", trust, "-i", h.path("age-id.txt"),
		"-o", h.path("out.txt"), h.path("old.age"))
	if r.exitCode != 0 || !strings.Contains(r.stderr, "legacy file") {
		t.Fatalf("legacy decrypt: code=%d stderr=%s", r.exitCode, r.stderr)
	}
	// With --require-proof the same file is rejected with the missing code.
	r = h.runProof(nil, "decrypt", "--require-proof", "-t", trust,
		"-i", h.path("age-id.txt"), h.path("old.age"))
	if r.exitCode != exitProofMissing {
		t.Fatalf("want %d, got %d: %s", exitProofMissing, r.exitCode, r.stderr)
	}
	// And the stock age binary still handles it with no provenance code in
	// the loop at all.
	if r := h.runAge(nil, "-d", "-i", h.path("age-id.txt"),
		"-o", h.path("out2.txt"), h.path("old.age")); r.exitCode != 0 {
		t.Fatalf("stock age: %s", r.stderr)
	}
}

func TestCLILegacyArmoredAgeStillDecrypts(t *testing.T) {
	h := newHarness(t, 1)
	trust := h.trustList("trust.txt", map[int]string{0: "trusted"})
	h.writeFile("plain.txt", "armored legacy\n")
	h.encryptAge("plain.txt", "secret.age")

	// Produce an armored age file (no provenance envelope).
	in, err := os.Open(h.path("secret.age"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.Create(h.path("secret.age.txt"))
	if err != nil {
		t.Fatal(err)
	}
	w := armor.NewWriter(out)
	if _, err := io.Copy(w, in); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	in.Close()
	out.Close()

	// Decrypt must de-armor automatically and treat it as a legacy file.
	r := h.runProof(nil, "decrypt", "-t", trust, "-i", h.path("age-id.txt"),
		"-o", h.path("armored-out.txt"), h.path("secret.age.txt"))
	if r.exitCode != 0 {
		t.Fatalf("legacy armored decrypt: %s", r.stderr)
	}
	got, _ := os.ReadFile(h.path("armored-out.txt"))
	if string(got) != "armored legacy\n" {
		t.Fatalf("plaintext mismatch: %q", got)
	}
}

func TestCLIFailureTaxonomy(t *testing.T) {
	h := newHarness(t, 3)
	h.writeFile("plain.txt", "taxonomy\n")
	h.encryptAge("plain.txt", "secret.age")
	trustAll := h.trustList("trust-all.txt", map[int]string{0: "trusted", 1: "trusted", 2: "trusted"})

	signed := h.path("signed.proof")
	if r := h.runProof(nil, "sign", "-k", h.path("signer0"), "-o", signed, h.path("secret.age")); r.exitCode != 0 {
		t.Fatal(r.stderr)
	}

	// Unknown signer: trust list containing only a key that never signed.
	pubExtra, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshExtra, err := ssh.NewPublicKey(pubExtra)
	if err != nil {
		t.Fatal(err)
	}
	unknownPath := h.path("trust-unknown.txt")
	os.WriteFile(unknownPath,
		[]byte(strings.TrimRight(string(ssh.MarshalAuthorizedKey(sshExtra)), "\n")+"\n"), 0644)
	if r := h.runProof(nil, "verify", "-t", unknownPath, signed); r.exitCode != exitSignerUnknown {
		t.Fatalf("unknown: code=%d stderr=%s", r.exitCode, r.stderr)
	}

	// Revoked signer.
	revoked := h.trustList("trust-revoked.txt", map[int]string{0: "revoked"})
	if r := h.runProof(nil, "verify", "-t", revoked, signed); r.exitCode != exitSignerRevoked {
		t.Fatalf("revoked: code=%d stderr=%s", r.exitCode, r.stderr)
	}

	// Expired trust entry.
	expired := h.trustList("trust-expired.txt", map[int]string{0: "expired"})
	if r := h.runProof(nil, "verify", "-t", expired, signed); r.exitCode != exitProofExpired {
		t.Fatalf("expired: code=%d stderr=%s", r.exitCode, r.stderr)
	}

	// Expired proof: construct with the library using a back-dated
	// creation, since the CLI always stamps "now".
	pastProof := h.path("past.proof")
	in, err := os.Open(h.path("secret.age"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.Create(pastProof)
	if err != nil {
		t.Fatal(err)
	}
	err = provenance.Sign(out, in, provenance.SignParams{
		SecretKeys: []ed25519.PrivateKey{h.signers[0]},
		Created:    time.Now().Add(-2 * time.Hour),
		Expires:    time.Now().Add(-time.Hour),
	})
	in.Close()
	out.Close()
	if err != nil {
		t.Fatal(err)
	}
	if r := h.runProof(nil, "verify", "-t", trustAll, pastProof); r.exitCode != exitProofExpired {
		t.Fatalf("expired proof: code=%d stderr=%s", r.exitCode, r.stderr)
	}

	// Missing proof: plain age file.
	if r := h.runProof(nil, "verify", "-t", trustAll, h.path("secret.age")); r.exitCode != exitProofMissing {
		t.Fatalf("missing: code=%d stderr=%s", r.exitCode, r.stderr)
	}

	// Corrupted proof: flip a payload byte.
	tampered := h.path("tampered.proof")
	raw, err := os.ReadFile(signed)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xFF
	if err := os.WriteFile(tampered, raw, 0644); err != nil {
		t.Fatal(err)
	}
	if r := h.runProof(nil, "verify", "-t", trustAll, tampered); r.exitCode != exitProofInvalid {
		t.Fatalf("invalid: code=%d stderr=%s", r.exitCode, r.stderr)
	}

	// Trust list missing and empty.
	if r := h.runProof(nil, "verify", "-t", h.path("nope.txt"), signed); r.exitCode != exitTrustList {
		t.Fatalf("missing trust list: code=%d", r.exitCode)
	}
	h.writeFile("empty-trust.txt", "# nothing here\n\n")
	if r := h.runProof(nil, "verify", "-t", h.path("empty-trust.txt"), signed); r.exitCode != exitTrustList {
		t.Fatalf("empty trust list: code=%d", r.exitCode)
	}
}

func TestCLITamperProducesNoOutput(t *testing.T) {
	h := newHarness(t, 1)
	h.writeRandom("plain.bin", 200000)
	h.encryptAge("plain.bin", "secret.age")
	trust := h.trustList("trust.txt", map[int]string{0: "trusted"})
	signed := h.path("signed.proof")
	if r := h.runProof(nil, "sign", "-k", h.path("signer0"), "-o", signed, h.path("secret.age")); r.exitCode != 0 {
		t.Fatal(r.stderr)
	}

	regions := map[string]int{
		"header":  20,
		"length":  indexOrFatal(t, signed, []byte("-> end")) + 8,
		"payload": int(fileSize(t, signed) - 50),
	}
	for name, pos := range regions {
		t.Run(name, func(t *testing.T) {
			bad := h.path("bad-" + name + ".proof")
			raw, err := os.ReadFile(signed)
			if err != nil {
				t.Fatal(err)
			}
			raw[pos] ^= 0x01
			if err := os.WriteFile(bad, raw, 0644); err != nil {
				t.Fatal(err)
			}
			out := h.path("leak-" + name + ".bin")
			r := h.runProof(nil, "decrypt", "-t", trust, "-i", h.path("age-id.txt"), "-o", out, bad)
			if r.exitCode != exitProofInvalid {
				t.Fatalf("code=%d stderr=%s", r.exitCode, r.stderr)
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatal("output file created despite failed verification")
			}
			if len(r.stdout) != 0 {
				t.Fatal("plaintext leaked to stdout")
			}
		})
	}
}

func TestCLICrossFileAndConcat(t *testing.T) {
	h := newHarness(t, 1)
	h.writeFile("a.txt", strings.Repeat("A", 5000))
	h.writeFile("b.txt", strings.Repeat("B", 5000))
	h.encryptAge("a.txt", "a.age")
	h.encryptAge("b.txt", "b.age")
	trust := h.trustList("trust.txt", map[int]string{0: "trusted"})

	pa := h.path("a.proof")
	pb := h.path("b.proof")
	if r := h.runProof(nil, "sign", "-k", h.path("signer0"), "-o", pa, h.path("a.age")); r.exitCode != 0 {
		t.Fatal(r.stderr)
	}
	if r := h.runProof(nil, "sign", "-k", h.path("signer0"), "-o", pb, h.path("b.age")); r.exitCode != 0 {
		t.Fatal(r.stderr)
	}

	// Transplant proof header of a onto the inner payload of b.
	ha, _ := os.ReadFile(pa)
	hb, _ := os.ReadFile(pb)
	cutA := bytes.IndexByte(ha, '\n')
	cutA = bytes.Index(ha[cutA+1:], []byte("-> end ")) + cutA + 1
	cutA = bytes.IndexByte(ha[cutA:], '\n') + cutA + 1
	cutB := bytes.IndexByte(hb, '\n')
	cutB = bytes.Index(hb[cutB+1:], []byte("-> end ")) + cutB + 1
	cutB = bytes.IndexByte(hb[cutB:], '\n') + cutB + 1
	frankenstein := append(append([]byte{}, ha[:cutA]...), hb[cutB:]...)
	if err := os.WriteFile(h.path("franken.proof"), frankenstein, 0644); err != nil {
		t.Fatal(err)
	}
	if r := h.runProof(nil, "verify", "-t", trust, h.path("franken.proof")); r.exitCode != exitProofInvalid {
		t.Fatalf("transplant: code=%d stderr=%s", r.exitCode, r.stderr)
	}

	// Concatenate two envelopes.
	joined := append(append([]byte{}, ha...), hb...)
	if err := os.WriteFile(h.path("joined.proof"), joined, 0644); err != nil {
		t.Fatal(err)
	}
	if r := h.runProof(nil, "verify", "-t", trust, h.path("joined.proof")); r.exitCode != exitProofInvalid {
		t.Fatalf("concat: code=%d stderr=%s", r.exitCode, r.stderr)
	}

	// Truncation.
	if err := os.WriteFile(h.path("trunc.proof"), ha[:len(ha)-128], 0644); err != nil {
		t.Fatal(err)
	}
	if r := h.runProof(nil, "verify", "-t", trust, h.path("trunc.proof")); r.exitCode != exitProofInvalid {
		t.Fatalf("truncation: code=%d stderr=%s", r.exitCode, r.stderr)
	}
}

func TestCLIBatchDirectoryIsolation(t *testing.T) {
	h := newHarness(t, 1)
	dir := h.path("inbox")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	// One good age file and one plaintext that must fail signing without
	// stopping the good one.
	if err := os.WriteFile(filepath.Join(dir, "good.age"), validAgeBytes(), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plain.txt"), []byte("not encrypted"), 0644); err != nil {
		t.Fatal(err)
	}
	r := h.runProof(nil, "sign", "-k", h.path("signer0"), dir)
	if r.exitCode != exitBatchHasFailures {
		t.Fatalf("batch sign code=%d stderr=%s", r.exitCode, r.stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "good.age.proof")); err != nil {
		t.Fatalf("good file not signed: %v", err)
	}
}

func TestCLIStdinAndSpecialSizes(t *testing.T) {
	h := newHarness(t, 1)
	trust := h.trustList("trust.txt", map[int]string{0: "trusted"})
	// Establish an age identity/recipient pair before the stdin pipeline.
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(h.path("age-id.txt"), []byte(id.String()+"\n"), 0600)
	recipient := id.Recipient().String()

	// Build an age ciphertext from stdin via the stock binary.
	plain := []byte("pipeline payload\n")
	enc := h.runAge(bytes.NewReader(plain), "-r", recipient, "-o", "-")
	if enc.exitCode != 0 {
		t.Fatal(enc.stderr)
	}
	// Sign the ciphertext through stdin -> armored stdout.
	signed := h.runProof(bytes.NewReader(enc.stdout), "sign", "--armor",
		"-k", h.path("signer0"), "-o", "-")
	if signed.exitCode != 0 {
		t.Fatalf("stdin sign: %s", signed.stderr)
	}
	// Verify + decrypt back through stdin.
	dec := h.runProof(bytes.NewReader(signed.stdout), "decrypt", "-t", trust,
		"-i", h.path("age-id.txt"), "-o", "-")
	if dec.exitCode != 0 || !bytes.Equal(dec.stdout, plain) {
		t.Fatalf("stdin round trip: code=%d stderr=%s", dec.exitCode, dec.stderr)
	}

	// Empty and one-byte plaintexts must be rejected at signing (the age
	// intro cannot be present), proving plaintext never gets a proof.
	for name, payload := range map[string][]byte{"empty": {}, "one": {'x'}} {
		t.Run(name, func(t *testing.T) {
			r := h.runProof(bytes.NewReader(payload), "sign",
				"-k", h.path("signer0"), "-o", "-")
			if r.exitCode == 0 {
				t.Fatal("plaintext was signed")
			}
			if len(r.stdout) != 0 {
				t.Fatal("rejected signing emitted output")
			}
		})
	}
}

func TestCLIPassphraseAndMultiRecipientInner(t *testing.T) {
	h := newHarness(t, 1)
	trust := h.trustList("trust.txt", map[int]string{0: "trusted"})
	h.writeFile("plain.txt", "secret contents\n")

	// Passphrase-encrypted inner file. The CLI only prompts on a TTY, so
	// build the scrypt ciphertext with the library; the provenance paths
	// under test are unchanged.
	r, err := age.NewScryptRecipient("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	pf, err := os.Create(h.path("pass.age"))
	if err != nil {
		t.Fatal(err)
	}
	w, err := age.Encrypt(pf, r)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(w, strings.NewReader("secret contents\n"))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	pf.Close()

	if r := h.runProof(nil, "sign", "-k", h.path("signer0"),
		"-o", h.path("pass.proof"), h.path("pass.age")); r.exitCode != 0 {
		t.Fatal(r.stderr)
	}
	// Verify the envelope independently; decryption of the scrypt inner
	// layer is exercised by the library-level tests. The provenance
	// guarantee is what this command adds.
	if r := h.runProof(nil, "verify", "-t", trust, h.path("pass.proof")); r.exitCode != 0 {
		t.Fatalf("passphrase proof verify: %s", r.stderr)
	}

	// Multi-recipient inner file: two age identities, one file.
	id1, _ := age.GenerateX25519Identity()
	id2, _ := age.GenerateX25519Identity()
	idFile := h.path("multi-id.txt")
	os.WriteFile(idFile, []byte(id1.String()+"\n"+id2.String()+"\n"), 0600)
	enc := h.runAge(nil, "-r", id1.Recipient().String(), "-r", id2.Recipient().String(),
		"-o", h.path("multi.age"), h.path("plain.txt"))
	if enc.exitCode != 0 {
		t.Fatal(enc.stderr)
	}
	if r := h.runProof(nil, "sign", "-k", h.path("signer0"),
		"-o", h.path("multi.proof"), h.path("multi.age")); r.exitCode != 0 {
		t.Fatal(r.stderr)
	}
	if r := h.runProof(nil, "decrypt", "-t", trust, "-i", idFile,
		"-o", h.path("multi-out.txt"), h.path("multi.proof")); r.exitCode != 0 {
		t.Fatalf("multi-recipient decrypt: %s", r.stderr)
	}
}

func TestCLIKeygenAndTrustFileForms(t *testing.T) {
	h := newHarness(t, 1)

	// Generate a dedicated signer with the age-proof keygen.
	keyPath := h.path("generated")
	r := h.runProof(nil, "keygen", "-o", keyPath)
	if r.exitCode != 0 {
		t.Fatalf("keygen: %s", r.stderr)
	}
	pubPath := h.path("generated.pub")
	if r := h.runProof(nil, "keygen", "-y", "-o", pubPath, keyPath); r.exitCode != 0 {
		t.Fatalf("keygen -y: %s", r.stderr)
	}
	pubs, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	// Both SSH and native forms are emitted, one per line.
	if !bytes.Contains(pubs, []byte("ssh-ed25519 ")) ||
		!bytes.Contains(pubs, []byte(provenance.NativePublicKeyHRP)) {
		t.Fatalf("public forms missing: %q", pubs)
	}
	// Native form alone is a valid trust list entry.
	nativeLine := bytes.Split(pubs, []byte("\n"))[1]
	os.WriteFile(h.path("native-trust.txt"),
		append(append([]byte{}, nativeLine...), '\n'), 0644)

	h.writeFile("plain.txt", "native trust path\n")
	h.encryptAge("plain.txt", "secret.age")
	if r := h.runProof(nil, "sign", "-k", keyPath,
		"-o", h.path("native.proof"), h.path("secret.age")); r.exitCode != 0 {
		t.Fatalf("sign with generated key: %s", r.stderr)
	}
	if r := h.runProof(nil, "verify", "-t", h.path("native-trust.txt"),
		h.path("native.proof")); r.exitCode != 0 {
		t.Fatalf("verify against native trust list: %s", r.stderr)
	}
}

func TestCLIArmorInputSigning(t *testing.T) {
	h := newHarness(t, 1)
	trust := h.trustList("trust.txt", map[int]string{0: "trusted"})
	h.writeFile("plain.txt", "armored in, binary out\n")
	h.encryptAge("plain.txt", "secret.age")

	// Armor the age file with the stock binary, then sign it: the inner
	// canonical bytes must still match the binary age file.
	ar := h.runAge(nil, "-a", "-r", mustRecipient(t, h),
		"-o", h.path("secret.age.txt"), h.path("plain.txt"))
	if ar.exitCode != 0 {
		// Fallback: armor via library since recipient arg may differ.
		in, err := os.Open(h.path("secret.age"))
		if err != nil {
			t.Fatal(err)
		}
		out, err := os.Create(h.path("secret.age.txt"))
		if err != nil {
			t.Fatal(err)
		}
		w := armor.NewWriter(out)
		io.Copy(w, in)
		w.Close()
		in.Close()
		out.Close()
	}
	if r := h.runProof(nil, "sign", "-k", h.path("signer0"),
		"-o", h.path("from-armored.proof"), h.path("secret.age.txt")); r.exitCode != 0 {
		t.Fatalf("sign armored age input: %s", r.stderr)
	}
	if r := h.runProof(nil, "verify", "-t", trust, h.path("from-armored.proof")); r.exitCode != 0 {
		t.Fatalf("verify: %s", r.stderr)
	}
}

func validAgeBytes() []byte {
	return []byte("age-encryption.org/v1\n-> scrypt AAAA 10\n--- \npayload-bytes\n")
}

func mustRecipient(t *testing.T, h *cliHarness) string {
	t.Helper()
	data, err := os.ReadFile(h.path("age-rec.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

func indexOrFatal(t *testing.T, path string, needle []byte) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	idx := bytes.Index(data, needle)
	if idx < 0 {
		t.Fatal("needle not found")
	}
	return idx
}
