// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

// This file implements batch mode, a separate entry point activated with
// --batch. It processes every regular file in an input directory and mirrors
// the directory structure into an output directory. The single-file code
// paths in age.go are not used or modified.
//
// Design properties:
//
//   - Files are processed one at a time, in sorted relative-path order. There
//     is no concurrency, so behavior is deterministic and a failure can never
//     corrupt another file's state.
//   - A file's identity is its relative path plus a SHA-256 content digest,
//     computed while streaming, so two different files sharing a path across
//     runs are distinguished.
//   - Each output is written to a temporary file and atomically renamed into
//     place. The progress state is itself replaced atomically (write to a
//     temp file, fsync, rename, fsync the directory), so a kill at any point
//     leaves either the previous complete state or the new complete state,
//     never a partial one.
//   - An existing output file that the state doesn't account for is never
//     overwritten: the entry is skipped and reported as a failure.
//   - No file is ever fully read into memory: the digest is computed in the
//     same streaming pass that encrypts or decrypts, in 32 KiB chunks.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

const (
	// batchStateName is the progress state file, kept inside the output
	// directory so a single directory carries the whole resumable run.
	batchStateName = ".age-batch-state.json"
	// batchStateVersion is bumped if the on-disk format changes.
	batchStateVersion = 1
	// batchTmpSuffix marks in-progress outputs. Any file ending in it is
	// treated as crash residue and removed before processing.
	batchTmpSuffix = ".age-batch-tmp"
	// batchCopyBufSize bounds the memory used per streaming copy.
	batchCopyBufSize = 32 << 10
)

// batchState is the on-disk progress document. It is only ever written by
// replacing the whole file atomically.
type batchState struct {
	Version int                   `json:"version"`
	Mode    string                `json:"mode"` // "encrypt" or "decrypt"
	Entries map[string]batchEntry `json:"entries"`
}

type batchEntry struct {
	// Digest is the hex-encoded SHA-256 of the input file's contents.
	Digest string `json:"digest"`
	// Output is the output path relative to the output directory.
	Output string `json:"output"`
}

type batchFailure struct {
	Rel   string
	Stage string
	Err   error
}

func (f batchFailure) String() string {
	return fmt.Sprintf("%s: %s: %v", f.Rel, f.Stage, f.Err)
}

type batchSummary struct {
	Total    int
	Success  int
	Skipped  int
	Failures []batchFailure
}

// runBatch validates the batch-specific configuration and executes the run.
// Configuration errors that make a run impossible as a whole call errorf,
// preserving the single-file exit-code behavior (exit 1 with an age: error).
func runBatch(decrypt bool, outDir string, recs, recFiles []string, idFlags identityFlags, armor bool) {
	if outDir == "" || outDir == "-" {
		errorf("batch mode requires an output directory with -o/--output")
	}
	// Interactive secrets and stdin/stdout don't make sense for an
	// unattended directory run.
	for _, f := range idFlags {
		if f.Value == "-" {
			errorf("standard input can't be used as a key file in batch mode")
		}
	}
	for _, f := range recFiles {
		if f == "-" {
			errorf("standard input can't be used as a recipients file in batch mode")
		}
	}

	inputDir := flag.Arg(0)
	if inputDir == "" || inputDir == "-" {
		errorf("batch mode requires an input directory argument")
	}
	inInfo, err := os.Stat(inputDir)
	if err != nil {
		errorf("failed to open input directory %q: %v", inputDir, err)
	}
	if !inInfo.IsDir() {
		errorf("batch input %q is not a directory", inputDir)
	}

	absIn, err := filepath.Abs(inputDir)
	if err != nil {
		errorf("failed to resolve input directory %q: %v", inputDir, err)
	}
	absOut, err := filepath.Abs(outDir)
	if err != nil {
		errorf("failed to resolve output directory %q: %v", outDir, err)
	}
	if absIn == absOut {
		errorf("batch input and output directories must be different: %q", absIn)
	}
	if isPathWithin(absOut, absIn) {
		errorf("batch output directory %q must not be inside the input directory %q", absOut, absIn)
	}

	// Resolve all keys before touching any data file, so a missing or
	// malformed key aborts the whole run up front.
	mode := "encrypt"
	var recipients []age.Recipient
	var identities []age.Identity
	if decrypt {
		mode = "decrypt"
		if len(idFlags) == 0 {
			errorf("batch decryption requires at least one -i/--identity file (passphrase mode is not supported)")
		}
		for _, f := range idFlags {
			switch f.Type {
			case "i":
				ids, err := parseIdentitiesFile(f.Value)
				if err != nil {
					errorf("reading %q: %v", f.Value, err)
				}
				identities = append(identities, ids...)
			default:
				errorf("plugin identities (-j) are not supported in batch mode")
			}
		}
		identities = append(identities, rejectScryptIdentity{})
	} else {
		for _, arg := range recs {
			r, err := parseRecipient(arg)
			if err != nil {
				errorf("%v", err)
			}
			recipients = append(recipients, r)
		}
		for _, name := range recFiles {
			rs, err := parseRecipientsFile(name)
			if err != nil {
				errorf("failed to parse recipient file %q: %v", name, err)
			}
			recipients = append(recipients, rs...)
		}
		for _, f := range idFlags {
			if f.Type != "i" {
				errorf("plugin identities (-j) are not supported in batch mode")
			}
			ids, err := parseIdentitiesFile(f.Value)
			if err != nil {
				errorf("reading %q: %v", f.Value, err)
			}
			rs, err := identitiesToRecipients(ids)
			if err != nil {
				errorf("internal error processing %q: %v", f.Value, err)
			}
			recipients = append(recipients, rs...)
		}
		if len(recipients) == 0 {
			errorf("missing recipients")
		}
	}

	// Refuse up front if the output directory can't be created or written.
	if err := ensureWritableOutputDir(absOut); err != nil {
		errorf("%v", err)
	}

	state, statePath, err := loadBatchState(absOut, mode)
	if err != nil {
		errorf("%v", err)
	}

	items, err := collectBatchItems(absIn)
	if err != nil {
		errorf("%v", err)
	}

	// Reject output-path collisions (e.g. a.age and a.age.age both decrypt to
	// a.age) before processing anything.
	outputs := make(map[string]string, len(items))
	for _, it := range items {
		out := batchOutputPath(it.rel, decrypt)
		if other, ok := outputs[out]; ok {
			errorf("input files %q and %q both map to output %q", other, it.rel, out)
		}
		outputs[out] = it.rel
	}

	if err := sweepBatchTempFiles(absOut); err != nil {
		errorf("failed to clean stale temporary files in %q: %v", absOut, err)
	}

	summary := batchSummary{Total: len(items)}
	for _, it := range items {
		status := processBatchItem(batchItemCtx{
			decrypt:    decrypt,
			armor:      armor,
			inDir:      absIn,
			outDir:     absOut,
			item:       it,
			state:      state,
			recipients: recipients,
			identities: identities,
		})
		switch status.kind {
		case batchSuccess:
			summary.Success++
		case batchSkipped:
			summary.Skipped++
		case batchFailed:
			summary.Failures = append(summary.Failures, status.failure)
		}
		// Persist after every unit of work, success or failure, so a kill at
		// any instant costs at most the file currently in flight.
		if err := writeBatchState(statePath, state); err != nil {
			errorf("failed to write batch state %q: %v", statePath, err)
		}
	}

	printBatchSummary(outDir, summary)
	if len(summary.Failures) > 0 {
		os.Exit(1)
	}
}

type batchItem struct {
	rel string
}

type batchItemCtx struct {
	decrypt    bool
	armor      bool
	inDir      string
	outDir     string
	item       batchItem
	state      *batchState
	recipients []age.Recipient
	identities []age.Identity
}

type batchStatus struct {
	kind    int // batchSuccess, batchSkipped, batchFailed
	failure batchFailure
}

const (
	batchSuccess = iota
	batchSkipped
	batchFailed
)

func processBatchItem(c batchItemCtx) batchStatus {
	rel := c.item.rel
	inPath := filepath.Join(c.inDir, rel)
	outRel := batchOutputPath(rel, c.decrypt)
	outPath := filepath.Join(c.outDir, outRel)

	// Re-stat before opening: a replacement since the directory walk must
	// not be processed under the walked metadata.
	before, err := os.Stat(inPath)
	if err != nil {
		return failBatch(c.state, rel, "stat input", err)
	}
	if !before.Mode().IsRegular() {
		return failBatch(c.state, rel, "stat input",
			fmt.Errorf("not a regular file (mode %s)", before.Mode()))
	}

	_, outputStatErr := os.Stat(outPath)
	outputExists := outputStatErr == nil

	if prev, ok := c.state.Entries[rel]; ok {
		if prev.Output != outRel {
			return failBatch(c.state, rel, "resume",
				fmt.Errorf("recorded output %q does not match expected output %q", prev.Output, outRel))
		}
		digest, derr := digestFile(inPath)
		if derr != nil {
			return failBatch(c.state, rel, "digest input", derr)
		}
		if digest != prev.Digest {
			// Same relative path, different content: the identity changed.
			// Refuse rather than silently overwrite the recorded output.
			return failBatch(c.state, rel, "resume",
				fmt.Errorf("input content changed since it was recorded; refusing to overwrite existing output %q", outRel))
		}
		if outputExists {
			// Identity matches and the output is in place: nothing to do.
			printf("skip %s (already completed)", rel)
			return batchStatus{kind: batchSkipped}
		}
		// Recorded entry whose output was deleted externally: the input is
		// unchanged, so regenerating the output is safe.
		printf("reprocessing %s (output missing)", rel)
	} else if outputExists {
		// Untracked existing output: never silently overwrite.
		return failBatch(c.state, rel, "open output",
			fmt.Errorf("output file %q already exists and is not tracked by the batch state; remove it to retry", outRel))
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return failBatch(c.state, rel, "create output directory", err)
	}

	tmpPath := outPath + batchTmpSuffix
	// Any leftover tmp for this entry is crash residue; remove before use.
	if err := os.Remove(tmpPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return failBatch(c.state, rel, "prepare output", err)
	}

	var digest string
	var perr error
	if c.decrypt {
		digest, perr = decryptOne(c.identities, inPath, tmpPath)
	} else {
		digest, perr = encryptOne(c.recipients, inPath, tmpPath, c.armor)
	}
	if perr != nil {
		if rmErr := os.Remove(tmpPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			warningf("failed to remove incomplete output %q: %v", tmpPath, rmErr)
		}
		var fe batchFileError
		if errors.As(perr, &fe) {
			return failBatch(c.state, rel, fe.Stage, fe.Err)
		}
		return failBatch(c.state, rel, "process", perr)
	}

	// Detect a file modified during the streaming pass: a size or
	// modification-time change means the digest can't be trusted. This uses
	// nanosecond-precision metadata like other backup tools, and discards
	// the output rather than renaming a possibly-inconsistent artifact.
	after, err := os.Stat(inPath)
	if err != nil {
		return failBatch(c.state, rel, "stat input", err)
	}
	if after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		if rmErr := os.Remove(tmpPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			warningf("failed to remove incomplete output %q: %v", tmpPath, rmErr)
		}
		return failBatch(c.state, rel, "verify input",
			fmt.Errorf("input file changed during processing; discarded the output, rerun to retry"))
	}

	if err := renameSync(tmpPath, outPath); err != nil {
		return failBatch(c.state, rel, "commit output", err)
	}

	// Record only after the output is durably in place.
	c.state.Entries[rel] = batchEntry{
		Digest: digest,
		Output: outRel,
	}
	printf("%s %s", batchDoneWord(c.decrypt), rel)
	return batchStatus{kind: batchSuccess}
}

func batchDoneWord(decrypt bool) string {
	if decrypt {
		return "decrypted"
	}
	return "encrypted"
}

// batchFileError annotates an error with the processing stage at which it
// occurred, so failures are specific to both file and stage.
type batchFileError struct {
	Stage string
	Err   error
}

func (e batchFileError) Error() string { return e.Err.Error() }
func (e batchFileError) Unwrap() error { return e.Err }

func failBatch(state *batchState, rel, stage string, err error) batchStatus {
	warningf("%s: %s: %v", rel, stage, err)
	return batchStatus{kind: batchFailed, failure: batchFailure{Rel: rel, Stage: stage, Err: err}}
}

// encryptOne streams inPath through age encryption into tmpPath while
// computing the SHA-256 of the plaintext in the same pass. Memory use is
// bounded by batchCopyBufSize regardless of file size.
func encryptOne(recipients []age.Recipient, inPath, tmpPath string, withArmor bool) (string, error) {
	in, err := os.Open(inPath)
	if err != nil {
		return "", batchFileError{Stage: "open input", Err: err}
	}
	defer in.Close()

	tmp, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", batchFileError{Stage: "open output", Err: err}
	}

	var out io.Writer = tmp
	var armorWriter io.WriteCloser
	if withArmor {
		armorWriter = armor.NewWriter(tmp)
		out = armorWriter
	}

	w, err := age.Encrypt(out, recipients...)
	if err != nil {
		tmp.Close()
		return "", batchFileError{Stage: "encrypt header", Err: err}
	}

	hashed := &hashingReader{r: in, h: sha256.New()}
	copyErr := copyBuffered(w, hashed)
	if copyErr == nil {
		copyErr = w.Close()
	}
	if copyErr == nil && armorWriter != nil {
		copyErr = armorWriter.Close()
	}
	if syncErr := tmp.Sync(); copyErr == nil && syncErr != nil {
		copyErr = syncErr
	}
	if closeErr := tmp.Close(); copyErr == nil && closeErr != nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		return "", batchFileError{Stage: "encrypt", Err: copyErr}
	}
	return hashed.digest(), nil
}

// decryptOne mirrors decrypt() in age.go (armor auto-detection included) but
// returns errors instead of exiting, and hashes the input ciphertext as it
// streams, so the file identity is computed without a second read.
func decryptOne(identities []age.Identity, inPath, tmpPath string) (string, error) {
	in, err := os.Open(inPath)
	if err != nil {
		return "", batchFileError{Stage: "open input", Err: err}
	}
	defer in.Close()

	hashed := &hashingReader{r: in, h: sha256.New()}
	rr := bufio.NewReader(hashed)
	const maxWhitespace = 1024
	start, _ := rr.Peek(maxWhitespace + len(armor.Header))
	var src io.Reader = rr
	if strings.HasPrefix(string(bytes.TrimSpace(start)), armor.Header) {
		src = armor.NewReader(rr)
	}

	r, err := age.Decrypt(src, identities...)
	if err != nil {
		return "", batchFileError{Stage: "decrypt header", Err: err}
	}

	tmp, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", batchFileError{Stage: "open output", Err: err}
	}
	copyErr := copyBuffered(tmp, r)
	if syncErr := tmp.Sync(); copyErr == nil && syncErr != nil {
		copyErr = syncErr
	}
	if closeErr := tmp.Close(); copyErr == nil && closeErr != nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		return "", batchFileError{Stage: "decrypt", Err: copyErr}
	}
	return hashed.digest(), nil
}

// hashingReader wraps a reader and accumulates a streaming SHA-256 of every
// byte read through it.
type hashingReader struct {
	r io.Reader
	h hash.Hash
}

func (t *hashingReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if n > 0 {
		t.h.Write(p[:n])
	}
	return n, err
}

func (t *hashingReader) digest() string { return hex.EncodeToString(t.h.Sum(nil)) }

// copyBuffered streams src into dst with a fixed-size buffer, never holding a
// whole file in memory.
func copyBuffered(dst io.Writer, src io.Reader) error {
	buf := make([]byte, batchCopyBufSize)
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

func digestFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.CopyBuffer(h, f, make([]byte, batchCopyBufSize)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func batchOutputPath(rel string, decrypt bool) string {
	if !decrypt {
		return rel + ".age"
	}
	if strings.HasSuffix(rel, ".age") {
		return strings.TrimSuffix(rel, ".age")
	}
	return rel + ".dec"
}

// collectBatchItems walks inDir and returns regular files as relative paths
// in deterministic order. Symlinks and other non-regular entries are skipped
// with a warning, as following them could escape the input directory.
func collectBatchItems(inDir string) ([]batchItem, error) {
	var items []batchItem
	err := filepath.WalkDir(inDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == inDir {
			return nil
		}
		rel, relErr := filepath.Rel(inDir, path)
		if relErr != nil {
			return relErr
		}
		if rel == batchStateName || strings.HasSuffix(rel, batchTmpSuffix) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		// WalkDir never follows symlinks: a symlink to a directory is
		// reported as a symlink entry, never descended into.
		if d.Type()&os.ModeSymlink != 0 {
			warningf("skipping symlink %q", rel)
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			warningf("skipping %q: not a regular file (mode %s)", rel, info.Mode())
			return nil
		}
		items = append(items, batchItem{rel: filepath.ToSlash(rel)})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk input directory %q: %w", inDir, err)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].rel < items[j].rel })
	return items, nil
}

// ensureWritableOutputDir creates the directory if needed and proves it is
// writable by creating and removing a probe file.
func ensureWritableOutputDir(dir string) error {
	if info, err := os.Stat(dir); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("output path %q exists and is not a directory", dir)
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("failed to create output directory %q: %w", dir, err)
		}
	} else {
		return fmt.Errorf("failed to stat output directory %q: %w", dir, err)
	}
	probe := filepath.Join(dir, ".age-batch-probe")
	f, err := os.OpenFile(probe, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("output directory %q is not writable: %w", dir, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("output directory %q probe failed: %w", dir, err)
	}
	if err := os.Remove(probe); err != nil {
		return fmt.Errorf("output directory %q probe failed: %w", dir, err)
	}
	return nil
}

func loadBatchState(outDir, mode string) (*batchState, string, error) {
	statePath := filepath.Join(outDir, batchStateName)
	state := &batchState{Version: batchStateVersion, Mode: mode, Entries: map[string]batchEntry{}}
	data, err := os.ReadFile(statePath)
	if errors.Is(err, os.ErrNotExist) {
		return state, statePath, nil
	}
	if err != nil {
		return nil, statePath, fmt.Errorf("failed to read batch state %q: %w", statePath, err)
	}
	var loaded batchState
	if err := json.Unmarshal(data, &loaded); err != nil {
		return nil, statePath, fmt.Errorf("batch state %q is corrupt: %w (remove it to start a fresh run)", statePath, err)
	}
	if loaded.Version != batchStateVersion {
		return nil, statePath, fmt.Errorf("batch state %q has unsupported version %d (remove it to start a fresh run)", statePath, loaded.Version)
	}
	if loaded.Mode != mode {
		return nil, statePath, fmt.Errorf("batch state %q records mode %q but the current run is %q (use a different output directory)", statePath, loaded.Mode, mode)
	}
	if loaded.Entries == nil {
		loaded.Entries = map[string]batchEntry{}
	}
	return &loaded, statePath, nil
}

// writeBatchState atomically replaces the state file: temp file, fsync,
// rename, fsync of the directory. A kill at any point leaves the old state or
// the complete new state, never a truncated document.
func writeBatchState(statePath string, state *batchState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(statePath)
	tmp, err := os.CreateTemp(dir, ".age-batch-state-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, statePath); err != nil {
		os.Remove(tmpName)
		return err
	}
	return syncDir(dir)
}

// sweepBatchTempFiles removes outputs left behind by a killed run. They are
// never renamed into place, so they are safe to delete unconditionally.
// Leftover temp files of the atomic state writer are removed as well.
func sweepBatchTempFiles(outDir string) error {
	return filepath.WalkDir(outDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		if strings.HasSuffix(path, batchTmpSuffix) ||
			strings.HasPrefix(base, ".age-batch-state-") && strings.HasSuffix(base, ".tmp") {
			if err := os.Remove(path); err != nil {
				return err
			}
			warningf("removed stale temporary output %q", path)
		}
		return nil
	})
}

func renameSync(old, new string) error {
	if err := os.Rename(old, new); err != nil {
		return err
	}
	return syncDir(filepath.Dir(new))
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if closeErr := d.Close(); err == nil {
		err = closeErr
	}
	return err
}

func isPathWithin(child, parent string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel)
}

func printBatchSummary(outDir string, s batchSummary) {
	printf("batch summary for %q: %d processed, %d succeeded, %d skipped, %d failed",
		outDir, s.Total, s.Success, s.Skipped, len(s.Failures))
	for _, f := range s.Failures {
		printf("batch failure: %s", f.String())
	}
}
