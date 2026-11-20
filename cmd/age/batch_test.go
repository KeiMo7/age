// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// batchTestKey generates a fresh X25519 identity and writes it to key.txt,
// returning the identity and the path of a matching recipient file.
func batchTestKey(t *testing.T, dir string) (identity *age.X25519Identity, keyPath, recipientsPath string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	keyPath = filepath.Join(dir, "key.txt")
	if err := os.WriteFile(keyPath, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	recipientsPath = filepath.Join(dir, "recipients.txt")
	if err := os.WriteFile(recipientsPath, []byte(id.Recipient().String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return id, keyPath, recipientsPath
}

// makeBatchTree creates a nested input tree with known contents, including an
// empty file and files large enough to span multiple 64 KiB stream chunks.
func makeBatchTree(t *testing.T, root string) map[string][]byte {
	t.Helper()
	want := map[string][]byte{
		"a.txt":                []byte("alpha\n"),
		"b/b.txt":              []byte(strings.Repeat("beta-content\n", 20000)),
		"b/c/c.txt":            []byte("gamma"),
		"b/c/empty.txt":        []byte(""),
		"d/deep/e/f/g/h/i.txt": []byte("nested\n"),
		"large.bin":            bytes.Repeat([]byte{0xab}, 300*1024),
		"unicode/文件-Ω.txt":     []byte("unicode contents\n"),
	}
	for rel, content := range want {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return want
}

func digestBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// readTree returns relative-path -> contents for every regular file under dir.
func readTree(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	got := map[string][]byte{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		got[filepath.ToSlash(rel)] = bytes.Clone(mustRead(t, path))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func batchAgePath(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "age-batch-test")
	cmd := exec.Command("go", "build", "-o", binary, ".")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	return binary
}

func runBatchCLI(t *testing.T, binary string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(binary, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stderr
	err := cmd.Run()
	if err == nil {
		return stderr.String(), 0
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("failed to run age: %v\n%s", err, stderr.String())
	}
	return stderr.String(), ee.ExitCode()
}

// TestBatchEncryptDecryptRoundTrip is the "normal batch" acceptance case:
// nested structure is mirrored and every plaintext round-trips.
func TestBatchEncryptDecryptRoundTrip(t *testing.T) {
	work := t.TempDir()
	in := filepath.Join(work, "in")
	enc := filepath.Join(work, "enc")
	dec := filepath.Join(work, "dec")
	if err := os.Mkdir(in, 0o755); err != nil {
		t.Fatal(err)
	}
	want := makeBatchTree(t, in)
	_, keyPath, recipientsPath := batchTestKey(t, work)
	binary := batchAgePath(t)

	log, code := runBatchCLI(t, binary, "--batch", "--encrypt",
		"-R", recipientsPath, "-o", enc, in)
	if code != 0 {
		t.Fatalf("encryption batch exited %d:\n%s", code, log)
	}

	encTree := readTree(t, enc)
	if _, ok := encTree[batchStateName]; !ok {
		t.Fatalf("progress state not found in output directory")
	}
	for rel := range want {
		if _, ok := encTree[rel+".age"]; !ok {
			t.Errorf("missing encrypted output for %q", rel)
		}
	}
	// No temporary files left behind.
	for rel := range encTree {
		if strings.HasSuffix(rel, batchTmpSuffix) {
			t.Errorf("stale temporary output %q", rel)
		}
	}

	log, code = runBatchCLI(t, binary, "--batch", "--decrypt",
		"-i", keyPath, "-o", dec, enc)
	if code != 0 {
		t.Fatalf("decryption batch exited %d:\n%s", code, log)
	}
	decTree := readTree(t, dec)
	for rel, content := range want {
		got, ok := decTree[rel]
		if !ok {
			t.Errorf("decrypted tree missing %q", rel)
			continue
		}
		if !bytes.Equal(got, content) {
			t.Errorf("content mismatch for %q", rel)
		}
	}
	// Summary numbers must appear on stderr.
	if !strings.Contains(log, "batch summary") ||
		!strings.Contains(log, "succeeded") {
		t.Errorf("missing batch summary in output:\n%s", log)
	}
}

// TestBatchSingleFileFailure proves one unreadable file only fails itself and
// the rest of the batch still completes, with a specific stage in the report.
func TestBatchSingleFileFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	work := t.TempDir()
	in := filepath.Join(work, "in")
	out := filepath.Join(work, "out")
	if err := os.MkdirAll(filepath.Join(in, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	contents := map[string]string{
		"ok1.txt":     "one",
		"sub/ok2.txt": "two",
		"denied.txt":  "secret",
	}
	for rel, c := range contents {
		if err := os.WriteFile(filepath.Join(in, filepath.FromSlash(rel)), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Make the input directory and one file unreadable. The file open fails
	// while the sibling files stay readable.
	if err := os.Chmod(filepath.Join(in, "denied.txt"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(in, "denied.txt"), 0o644) })

	_, _, recipientsPath := batchTestKey(t, work)
	binary := batchAgePath(t)
	log, code := runBatchCLI(t, binary, "--batch", "-e",
		"-R", recipientsPath, "-o", out, in)
	if code != 1 {
		t.Fatalf("expected exit 1 with a failed file, got %d:\n%s", code, log)
	}
	if !strings.Contains(log, "denied.txt") || !strings.Contains(log, "open input") {
		t.Errorf("failure must name the file and stage, got:\n%s", log)
	}
	if !strings.Contains(log, "1 failed") {
		t.Errorf("summary must report exactly one failure:\n%s", log)
	}
	for _, rel := range []string{"ok1.txt.age", "sub/ok2.txt.age"} {
		if _, err := os.Stat(filepath.Join(out, filepath.FromSlash(rel))); err != nil {
			t.Errorf("sibling %q should have been processed despite the failure: %v", rel, err)
		}
	}
	// The failed file must not have produced an output.
	if _, err := os.Stat(filepath.Join(out, "denied.txt.age")); !os.IsNotExist(err) {
		t.Errorf("failed file produced an output")
	}

	// Fix the permission and rerun: the two good files are skipped, the
	// previously failed one now succeeds.
	if err := os.Chmod(filepath.Join(in, "denied.txt"), 0o644); err != nil {
		t.Fatal(err)
	}
	log, code = runBatchCLI(t, binary, "--batch", "-e",
		"-R", recipientsPath, "-o", out, in)
	if code != 0 {
		t.Fatalf("rerun after fixing the file exited %d:\n%s", code, log)
	}
	if !strings.Contains(log, "2 skipped") || !strings.Contains(log, "1 succeeded") {
		t.Errorf("rerun should skip 2 and succeed 1:\n%s", log)
	}
}

// TestBatchResumeAfterInterrupt drives a partial run, then resumes it, and
// asserts the resumed output tree is byte-identical to a one-shot run.
func TestBatchResumeAfterInterrupt(t *testing.T) {
	work := t.TempDir()
	in := filepath.Join(work, "in")
	outResume := filepath.Join(work, "resume")
	outFresh := filepath.Join(work, "fresh")
	if err := os.Mkdir(in, 0o755); err != nil {
		t.Fatal(err)
	}
	want := makeBatchTree(t, in)
	_, _, recipientsPath := batchTestKey(t, work)
	binary := batchAgePath(t)

	// First run: kill the process after it commits a few files by removing
	// read permission from a mid-tree file once earlier outputs exist.
	stopper := filepath.Join(in, "b", "c", "c.txt")
	if err := os.Chmod(stopper, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(stopper, 0o644) })
	log, code := runBatchCLI(t, binary, "--batch", "-e",
		"-R", recipientsPath, "-o", outResume, in)
	if code != 1 {
		t.Fatalf("interrupted-style run should exit 1, got %d:\n%s", code, log)
	}
	state := readBatchState(t, filepath.Join(outResume, batchStateName))
	if len(state.Entries) == 0 {
		t.Fatal("interrupted run recorded no progress")
	}
	if len(state.Entries) >= len(want) {
		t.Fatalf("interruption didn't interrupt: %d/%d entries", len(state.Entries), len(want))
	}

	// Resume with the permission restored.
	if err := os.Chmod(stopper, 0o644); err != nil {
		t.Fatal(err)
	}
	log, code = runBatchCLI(t, binary, "--batch", "-e",
		"-R", recipientsPath, "-o", outResume, in)
	if code != 0 {
		t.Fatalf("resumed run exited %d:\n%s", code, log)
	}
	if !strings.Contains(log, "skipped") {
		t.Errorf("resumed run must skip already completed files:\n%s", log)
	}

	// A clean one-shot run against the same input tree.
	_, code = runBatchCLI(t, binary, "--batch", "-e",
		"-R", recipientsPath, "-o", outFresh, in)
	if code != 0 {
		t.Fatalf("one-shot run failed")
	}

	resumed := readTree(t, outResume)
	fresh := readTree(t, outFresh)
	// Compare everything except the state file itself (it embeds no random
	// output, but keep the comparison focused on the encrypted artifacts).
	delete(resumed, batchStateName)
	delete(fresh, batchStateName)
	if len(resumed) != len(fresh) {
		t.Fatalf("resumed run produced %d files, one-shot produced %d", len(resumed), len(fresh))
	}
	// Ciphertexts include random nonces, so compare decrypted content instead
	// of raw bytes: decrypt both trees and assert identical plaintexts.
	decResume := filepath.Join(work, "dec-resume")
	decFresh := filepath.Join(work, "dec-fresh")
	keyPath := filepath.Join(work, "key.txt")
	_, code = runBatchCLI(t, binary, "--batch", "-d", "-i", keyPath, "-o", decResume, outResume)
	if code != 0 {
		t.Fatal("decrypt resumed outputs")
	}
	_, code = runBatchCLI(t, binary, "--batch", "-d", "-i", keyPath, "-o", decFresh, outFresh)
	if code != 0 {
		t.Fatal("decrypt fresh outputs")
	}
	gotResume := readTree(t, decResume)
	gotFresh := readTree(t, decFresh)
	delete(gotResume, batchStateName)
	delete(gotFresh, batchStateName)
	keysResume := sortedKeys(gotResume)
	keysFresh := sortedKeys(gotFresh)
	if !slices.Equal(keysResume, keysFresh) {
		t.Fatalf("decrypted path sets differ:\n%v\n%v", keysResume, keysFresh)
	}
	for rel := range gotResume {
		if !bytes.Equal(gotResume[rel], gotFresh[rel]) {
			t.Errorf("resumed vs one-shot plaintext differs for %q", rel)
		}
		if !bytes.Equal(gotResume[rel], want[rel]) {
			t.Errorf("plaintext for %q does not match the original input", rel)
		}
	}
}

func sortedKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// TestBatchNoSilentOverwrite asserts an untracked, pre-existing output file is
// refused rather than overwritten, and that rerunning a completed batch only
// skips entries without touching outputs.
func TestBatchNoSilentOverwrite(t *testing.T) {
	work := t.TempDir()
	in := filepath.Join(work, "in")
	out := filepath.Join(work, "out")
	if err := os.MkdirAll(filepath.Join(in, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in, "a.txt"), []byte("aaa"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in, "sub", "b.txt"), []byte("bbb"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, recipientsPath := batchTestKey(t, work)
	binary := batchAgePath(t)

	// Plant an untracked output.
	planted := filepath.Join(out, "a.txt.age")
	if err := os.MkdirAll(filepath.Dir(planted), 0o755); err != nil {
		t.Fatal(err)
	}
	marker := []byte("do-not-overwrite")
	if err := os.WriteFile(planted, marker, 0o644); err != nil {
		t.Fatal(err)
	}
	log, code := runBatchCLI(t, binary, "--batch", "-e",
		"-R", recipientsPath, "-o", out, in)
	if code != 1 {
		t.Fatalf("expected exit 1 due to existing output, got %d", code)
	}
	if got := mustRead(t, planted); !bytes.Equal(got, marker) {
		t.Errorf("existing output was overwritten")
	}
	if !strings.Contains(log, "already exists") {
		t.Errorf("expected an explicit refusal message:\n%s", log)
	}
	// The other file should still have been processed.
	if _, err := os.Stat(filepath.Join(out, "sub", "b.txt.age")); err != nil {
		t.Errorf("unrelated file should have been processed: %v", err)
	}

	// Remove the planted file and rerun: both succeed, then a third run skips
	// everything and leaves outputs untouched.
	if err := os.Remove(planted); err != nil {
		t.Fatal(err)
	}
	_, code = runBatchCLI(t, binary, "--batch", "-e",
		"-R", recipientsPath, "-o", out, in)
	if code != 0 {
		t.Fatal("rerun after removing conflict should succeed")
	}
	firstA := mustRead(t, filepath.Join(out, "a.txt.age"))
	log, code = runBatchCLI(t, binary, "--batch", "-e",
		"-R", recipientsPath, "-o", out, in)
	if code != 0 {
		t.Fatalf("idempotent rerun should exit 0, got %d", code)
	}
	if !strings.Contains(log, "2 skipped") {
		t.Errorf("completed entries must be skipped:\n%s", log)
	}
	if got := mustRead(t, filepath.Join(out, "a.txt.age")); !bytes.Equal(got, firstA) {
		t.Errorf("skipped output was modified on rerun")
	}
}

// TestBatchStartupChecks covers pre-flight rejections: unwritable output
// directory, missing/malformed keys, and stdin/passphrase misuse. Nothing is
// processed before these errors.
func TestBatchStartupChecks(t *testing.T) {
	work := t.TempDir()
	in := filepath.Join(work, "in")
	if err := os.MkdirAll(in, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in, "x.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, keyPath, recipientsPath := batchTestKey(t, work)
	binary := batchAgePath(t)

	// Unwritable output directory (skip under root).
	if os.Geteuid() != 0 {
		ro := filepath.Join(work, "readonly")
		if err := os.Mkdir(ro, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(ro, 0o755) })
		log, code := runBatchCLI(t, binary, "--batch", "-e",
			"-R", recipientsPath, "-o", ro, in)
		if code != 1 || !strings.Contains(log, "not writable") {
			t.Errorf("unwritable output must be rejected at startup, got %d:\n%s", code, log)
		}
		if got := readTree(t, ro); len(got) != 0 {
			t.Errorf("startup failure left files behind: %v", got)
		}
	}

	// Missing recipient file.
	log, code := runBatchCLI(t, binary, "--batch", "-e",
		"-R", filepath.Join(work, "nope.txt"), "-o", filepath.Join(work, "o1"), in)
	if code != 1 || !strings.Contains(log, "failed to open recipient file") {
		t.Errorf("missing recipient file must fail before processing, got %d:\n%s", code, log)
	}

	// Malformed identity file.
	badKey := filepath.Join(work, "bad.txt")
	if err := os.WriteFile(badKey, []byte("not-a-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	log, code = runBatchCLI(t, binary, "--batch", "-d",
		"-i", badKey, "-o", filepath.Join(work, "o2"), in)
	if code != 1 || !strings.Contains(log, "unknown identity type") {
		t.Errorf("malformed identity must fail before processing, got %d:\n%s", code, log)
	}

	// Passphrase and stdin rejections.
	if _, code := runBatchCLI(t, binary, "--batch", "-p",
		"-o", filepath.Join(work, "o3"), in); code != 1 {
		t.Errorf("passphrase batch mode must be rejected")
	}
	if _, code := runBatchCLI(t, binary, "--batch", "-d",
		"-i", "-", "-o", filepath.Join(work, "o4"), in); code != 1 {
		t.Errorf("stdin identity must be rejected in batch mode")
	}
	if _, code := runBatchCLI(t, binary, "--batch", "-e",
		"-R", recipientsPath, "-o", in, in); code != 1 {
		t.Errorf("input==output directory must be rejected")
	}
	_ = keyPath
}

// TestBatchInputModifiedDuringProcessing changes an input file after its
// processing started (simulated by a state entry pointing at changed content)
// and asserts the run refuses to overwrite the recorded output.
func TestBatchInputModifiedBetweenRuns(t *testing.T) {
	work := t.TempDir()
	in := filepath.Join(work, "in")
	out := filepath.Join(work, "out")
	if err := os.Mkdir(in, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(in, "data.txt")
	if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, recipientsPath := batchTestKey(t, work)
	binary := batchAgePath(t)

	if _, code := runBatchCLI(t, binary, "--batch", "-e",
		"-R", recipientsPath, "-o", out, in); code != 0 {
		t.Fatal("initial batch failed")
	}
	firstOut := mustRead(t, filepath.Join(out, "data.txt.age"))

	// Same relative path, different content: identity must distinguish them.
	if err := os.WriteFile(target, []byte("modified-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	log, code := runBatchCLI(t, binary, "--batch", "-e",
		"-R", recipientsPath, "-o", out, in)
	if code != 1 {
		t.Fatalf("changed input must be refused, got exit %d", code)
	}
	if !strings.Contains(log, "input content changed") {
		t.Errorf("expected a content-change error:\n%s", log)
	}
	if got := mustRead(t, filepath.Join(out, "data.txt.age")); !bytes.Equal(got, firstOut) {
		t.Errorf("recorded output was overwritten despite changed input")
	}
}

// TestBatchStateIsAtomic kills a run mid-flight and asserts the state file is
// always complete, valid JSON with a matching schema version.
func TestBatchStateIsAtomic(t *testing.T) {
	work := t.TempDir()
	in := filepath.Join(work, "in")
	out := filepath.Join(work, "out")
	if err := os.Mkdir(in, 0o755); err != nil {
		t.Fatal(err)
	}
	// Files big enough that processing the whole tree takes a while, so a
	// SIGKILL after the first state commit reliably lands mid-run.
	for i := range 60 {
		p := filepath.Join(in, "uniq", "u"+itoa(i)+".txt")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, bytes.Repeat([]byte{byte('a' + i%26)}, 512*1024), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_, _, recipientsPath := batchTestKey(t, work)
	binary := batchAgePath(t)

	// Start the run, wait until the first state commit proves progress, then
	// SIGKILL it so remaining files are still pending.
	cmd := exec.Command(binary, "--batch", "-e", "-R", recipientsPath, "-o", out, in)
	var runLog bytes.Buffer
	cmd.Stderr = &runLog
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(out, batchStateName)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(statePath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("state file never appeared:\n%s", runLog.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_, _ = cmd.Process.Wait()

	state := readBatchState(t, statePath)
	if state.Version != batchStateVersion || state.Mode != "encrypt" {
		t.Fatalf("state header invalid: %+v", state)
	}
	if len(state.Entries) == 0 || len(state.Entries) >= 60 {
		t.Fatalf("kill did not land mid-run: %d/60 entries", len(state.Entries))
	}
	// Every recorded entry must correspond to a fully renamed output.
	for rel, e := range state.Entries {
		p := filepath.Join(out, filepath.FromSlash(e.Output))
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("state records %q but output is missing: %v", rel, err)
		}
		if info.Size() == 0 {
			t.Errorf("output for %q looks truncated", rel)
		}
	}
	// Completing the run after the kill must succeed and cover every input.
	_, code := runBatchCLI(t, binary, "--batch", "-e", "-R", recipientsPath, "-o", out, in)
	if code != 0 {
		t.Fatal("run after SIGKILL did not complete cleanly")
	}
	final := readBatchState(t, filepath.Join(out, batchStateName))
	tree := readTree(t, in)
	if len(final.Entries) != len(tree) {
		t.Fatalf("completed state has %d entries for %d input files", len(final.Entries), len(tree))
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}

func readBatchState(t *testing.T, path string) batchState {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("state file unreadable: %v", err)
	}
	var s batchState
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("state file is not valid JSON after interruption: %v", err)
	}
	return s
}

// TestBatchDigestIdentity verifies the state digest equals the SHA-256 of the
// recorded input file content, i.e. path + content identity.
func TestBatchDigestIdentity(t *testing.T) {
	work := t.TempDir()
	in := filepath.Join(work, "in")
	out := filepath.Join(work, "out")
	if err := os.Mkdir(in, 0o755); err != nil {
		t.Fatal(err)
	}
	want := makeBatchTree(t, in)
	_, _, recipientsPath := batchTestKey(t, work)
	binary := batchAgePath(t)
	if _, code := runBatchCLI(t, binary, "--batch", "-e",
		"-R", recipientsPath, "-o", out, in); code != 0 {
		t.Fatal("batch failed")
	}
	state := readBatchState(t, filepath.Join(out, batchStateName))
	for rel, content := range want {
		e, ok := state.Entries[rel]
		if !ok {
			t.Errorf("state missing entry %q", rel)
			continue
		}
		if e.Digest != digestBytes(content) {
			t.Errorf("digest mismatch for %q", rel)
		}
		if e.Output != rel+".age" {
			t.Errorf("output mapping wrong for %q: %q", rel, e.Output)
		}
	}
}

// TestBatchArmorRoundTrip checks armored batch outputs (PEM text) round-trip
// and are auto-detected during batch decryption.
func TestBatchArmorRoundTrip(t *testing.T) {
	work := t.TempDir()
	in := filepath.Join(work, "in")
	enc := filepath.Join(work, "enc")
	dec := filepath.Join(work, "dec")
	if err := os.MkdirAll(filepath.Join(in, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	content := []byte(strings.Repeat("armored payload\n", 5000))
	if err := os.WriteFile(filepath.Join(in, "nested", "a.txt"), content, 0o644); err != nil {
		t.Fatal(err)
	}
	_, keyPath, recipientsPath := batchTestKey(t, work)
	binary := batchAgePath(t)

	if _, code := runBatchCLI(t, binary, "--batch", "-e", "-a",
		"-R", recipientsPath, "-o", enc, in); code != 0 {
		t.Fatal("armored encryption failed")
	}
	encrypted := mustRead(t, filepath.Join(enc, "nested", "a.txt.age"))
	if !bytes.Contains(encrypted, []byte("-----BEGIN AGE ENCRYPTED FILE-----")) {
		t.Fatal("armored output is not PEM encoded")
	}
	if _, code := runBatchCLI(t, binary, "--batch", "-d",
		"-i", keyPath, "-o", dec, enc); code != 0 {
		t.Fatal("armored decryption failed")
	}
	if got := mustRead(t, filepath.Join(dec, "nested", "a.txt")); !bytes.Equal(got, content) {
		t.Errorf("armored round-trip content mismatch")
	}
}

// TestBatchDecryptSuffixFallback checks files without an .age suffix decrypt
// to a .dec output rather than colliding with the input naming.
func TestBatchDecryptSuffixFallback(t *testing.T) {
	work := t.TempDir()
	in := filepath.Join(work, "in")
	enc := filepath.Join(work, "enc")
	dec := filepath.Join(work, "dec")
	if err := os.Mkdir(in, 0o755); err != nil {
		t.Fatal(err)
	}
	plain := []byte("suffix fallback")
	src := filepath.Join(in, "blob")
	if err := os.WriteFile(src, plain, 0o644); err != nil {
		t.Fatal(err)
	}
	_, keyPath, recipientsPath := batchTestKey(t, work)
	binary := batchAgePath(t)

	// Encrypt single-file style to produce an output without an .age suffix,
	// then place it into a directory for batch decryption.
	if err := os.Mkdir(enc, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, code := runBatchCLI(t, binary, "-e", "-R", recipientsPath,
		"-o", filepath.Join(enc, "blob"), src); code != 0 {
		t.Fatal("single-file encryption setup failed")
	}
	if _, code := runBatchCLI(t, binary, "--batch", "-d",
		"-i", keyPath, "-o", dec, enc); code != 0 {
		t.Fatal("batch decryption failed")
	}
	if got := mustRead(t, filepath.Join(dec, "blob.dec")); !bytes.Equal(got, plain) {
		t.Errorf(".dec fallback content mismatch")
	}
}

// TestBatchUnwritableOutputAtStartup proves nothing is created when the output
// directory exists but cannot be written (probe file creation fails).
func TestBatchUnwritableOutputAtStartup(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	work := t.TempDir()
	in := filepath.Join(work, "in")
	ro := filepath.Join(work, "ro")
	if err := os.MkdirAll(filepath.Join(in, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in, "sub", "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o755) })
	_, _, recipientsPath := batchTestKey(t, work)
	binary := batchAgePath(t)
	log, code := runBatchCLI(t, binary, "--batch", "-e",
		"-R", recipientsPath, "-o", ro, in)
	if code != 1 || !strings.Contains(log, "not writable") {
		t.Fatalf("unwritable output must be rejected at startup, got %d:\n%s", code, log)
	}
	if got := readTree(t, ro); len(got) != 0 {
		t.Errorf("startup rejection left files behind: %v", got)
	}
}
