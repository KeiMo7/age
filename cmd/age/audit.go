// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"time"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/plugin"
)

// This file implements the opt-in decryption audit log enabled by the
// --audit-log flag.
//
// The log is a JSON Lines file: every decryption attempt appends one record
// per identity that was tried, plus one file-level record with the overall
// outcome. Records never contain private or symmetric key material, only
// public identifiers (recipient encodings or SSH key fingerprints), and all
// paths are stored relative to the working directory.
//
// Audit logging must never affect the decryption flow: if the log can't be
// opened or a record can't be written, a warning is printed and decryption
// continues. Records are written unbuffered, one write(2) per record, so
// that records produced before the process is killed are already on disk.

// auditRecordVersion is the version of the audit record schema. The
// semantics of version 1 records are frozen: future versions may add
// fields, but the meaning of existing fields must not change.
const auditRecordVersion = 1

// Failure categories recorded in the "failure" field of audit records.
const (
	// failureIdentityMismatch means the identity did not match any of the
	// file's recipients (or, for passphrase-encrypted files, the
	// passphrase was incorrect).
	failureIdentityMismatch = "identity_mismatch"
	// failureCorruptFile means the input could not be parsed or
	// authenticated as an age file.
	failureCorruptFile = "corrupt_file"
	// failureMissingRecipient means no supplied identity matched any of
	// the recipients the file was encrypted to.
	failureMissingRecipient = "missing_recipient"
	// failureReadDenied means the input file could not be opened for
	// reading.
	failureReadDenied = "read_denied"
	// failureIdentityError means an identity failed for a reason other
	// than not matching (e.g. an encrypted identity file could not be
	// decrypted, or a plugin returned an error).
	failureIdentityError = "identity_error"
	// failurePluginMissing means a required plugin binary was not found.
	failurePluginMissing = "plugin_missing"
)

// auditRecord is a single line of the audit log.
type auditRecord struct {
	Version      int    `json:"v"`
	Time         string `json:"time"`
	Kind         string `json:"kind"` // "identity" or "file"
	Identity     string `json:"identity,omitempty"`
	IdentityType string `json:"identity_type,omitempty"`
	File         string `json:"file"`
	Result       string `json:"result"`            // "success" or "failure"
	Failure      string `json:"failure,omitempty"` // one of the failure* constants
}

// theAuditor is the process-wide auditor, nil unless --audit-log was
// provided and the log file could be opened.
var theAuditor *auditor

type auditor struct {
	f      *os.File
	path   string
	target string // relativized name of the file being decrypted

	matched     string // label of the identity that unwrapped the file key
	identityErr error  // last non-mismatch error returned by an identity

	skipped int      // records dropped because they failed to serialize
	pending [][]byte // records that failed to write, kept for later retry
}

// newAuditor opens the audit log at path for appending. If the file (or its
// directory) is not writable, it prints a warning and returns nil, so that
// decryption proceeds without audit logging.
func newAuditor(path string) *auditor {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		warningf("cannot open audit log %q, continuing without audit logging: %v", path, err)
		return nil
	}
	return &auditor{f: f, path: path}
}

// writeRecord serializes and appends a single record. Serialization
// failures are counted and the record is skipped; write failures are
// retained in memory and retried on the next record and at close.
func (a *auditor) writeRecord(r auditRecord) {
	line, err := json.Marshal(r)
	if err != nil {
		a.skipped++
		return
	}
	a.writeLine(append(line, '\n'))
}

func (a *auditor) writeLine(line []byte) {
	// Retry records that failed to be written earlier, so that a
	// transient failure (e.g. a briefly full filesystem) is backfilled
	// automatically.
	if len(a.pending) > 0 {
		pending := a.pending
		a.pending = nil
		for _, p := range pending {
			a.writeLine(p)
		}
	}
	// A single unbuffered write per record: records produced before the
	// process is killed are already complete on disk, never half a line.
	if _, err := a.f.Write(line); err != nil {
		warningf("failed to write audit record to %q, will retry: %v", a.path, err)
		a.pending = append(a.pending, line)
	}
}

// close makes a final attempt to write pending records and closes the log.
// It is idempotent and of course safe to call on a nil auditor.
func (a *auditor) close() {
	if a == nil || a.f == nil {
		return
	}
	if len(a.pending) > 0 {
		pending := a.pending
		a.pending = nil
		for _, p := range pending {
			if _, err := a.f.Write(p); err != nil {
				a.pending = append(a.pending, p)
			}
		}
	}
	if a.skipped > 0 {
		warningf("%d audit records failed to serialize and were skipped", a.skipped)
	}
	if len(a.pending) > 0 {
		warningf("%d audit records could not be written to %q", len(a.pending), a.path)
	}
	a.f.Close()
	a.f = nil
}

// flushAudit flushes and closes the audit log. It is called before the
// process exits through errorf or errorWithHint, since os.Exit skips
// deferred functions.
func flushAudit() {
	theAuditor.close()
}

// recordIdentityAttempt records the outcome of a single identity's Unwrap
// call. It never sees the file key, only the error.
func (a *auditor) recordIdentityAttempt(label, typ string, err error) {
	r := auditRecord{
		Version:      auditRecordVersion,
		Time:         time.Now().UTC().Format(time.RFC3339Nano),
		Kind:         "identity",
		Identity:     label,
		IdentityType: typ,
		File:         a.target,
	}
	switch {
	case err == nil:
		r.Result = "success"
		a.matched = label
	case errors.Is(err, age.ErrIncorrectIdentity) || errors.Is(err, errIncorrectPassphrase):
		r.Result, r.Failure = "failure", failureIdentityMismatch
	default:
		r.Result, r.Failure = "failure", failureIdentityError
		a.identityErr = err
	}
	a.writeRecord(r)
}

// recordFileOutcome records the file-level outcome of a decryption attempt.
func (a *auditor) recordFileOutcome(result, failure string) {
	a.writeRecord(auditRecord{
		Version:  auditRecordVersion,
		Time:     time.Now().UTC().Format(time.RFC3339Nano),
		Kind:     "file",
		Identity: a.matched,
		File:     a.target,
		Result:   result,
		Failure:  failure,
	})
}

// classifyDecryptError maps an error returned by age.Decrypt to a failure
// category.
func (a *auditor) classifyDecryptError(err error) string {
	switch {
	case errors.As(err, new(*age.NoIdentityMatchError)):
		return failureMissingRecipient
	case errors.Is(err, errIncorrectPassphrase):
		return failureIdentityMismatch
	case errors.As(err, new(*plugin.NotFoundError)):
		return failurePluginMissing
	case a.identityErr != nil && errors.Is(err, a.identityErr):
		// The error came out of an identity's Unwrap (e.g. an encrypted
		// identity file that couldn't be decrypted), not from parsing
		// the target file.
		return failureIdentityError
	default:
		// Header parsing, MAC verification, and payload read failures.
		return failureCorruptFile
	}
}

// auditIdentity wraps an age.Identity to record every Unwrap attempt. It
// never observes key material: Unwrap returns the file key directly to the
// caller, and only the error is inspected.
type auditIdentity struct {
	age.Identity
	label, typ string
	audit      *auditor
}

func (w *auditIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	fileKey, err := w.Identity.Unwrap(stanzas)
	w.audit.recordIdentityAttempt(w.label, w.typ, err)
	return fileKey, err
}

// wrapIdentity wraps id for audit logging. source is the name of the file
// the identity was loaded from, if any.
func (a *auditor) wrapIdentity(id age.Identity, source string) age.Identity {
	label, typ := auditIdentityLabel(id, source)
	return &auditIdentity{Identity: id, label: label, typ: typ, audit: a}
}

// wrapAuditIdentities wraps a batch of identities loaded from source. It is
// a no-op when audit logging is disabled.
func wrapAuditIdentities(ids []age.Identity, source string) []age.Identity {
	if theAuditor == nil {
		return ids
	}
	wrapped := make([]age.Identity, len(ids))
	for i, id := range ids {
		wrapped[i] = theAuditor.wrapIdentity(id, source)
	}
	return wrapped
}

// auditIdentityLabel returns a non-secret identifier for an identity: a
// public key encoding or SSH fingerprint when available, otherwise a
// reference to the (relativized) file the identity was loaded from.
func auditIdentityLabel(id age.Identity, source string) (label, typ string) {
	if source != "" {
		source = relativizePath(source)
	}
	switch id := id.(type) {
	case *age.X25519Identity:
		return id.Recipient().String(), "x25519"
	case *age.HybridIdentity:
		return id.Recipient().String(), "hybrid"
	case *plugin.Identity:
		return "plugin:" + id.Name(), "plugin"
	case *agessh.RSAIdentity:
		return id.SSHFingerprint(), "ssh-rsa"
	case *agessh.Ed25519Identity:
		return id.SSHFingerprint(), "ssh-ed25519"
	case *agessh.EncryptedSSHIdentity:
		return id.SSHFingerprint(), "ssh-encrypted"
	case *EncryptedIdentity:
		return "file:" + source, "encrypted-identity"
	case *LazyScryptIdentity:
		return "scrypt", "scrypt"
	default:
		return "file:" + source, "unknown"
	}
}

// sortAuditIdentities replicates the native-first ordering that age.Decrypt
// applies internally, so that wrapping identities in auditIdentity (which
// hides their concrete type from that sort) does not change the order in
// which they are tried.
func sortAuditIdentities(ids []age.Identity) {
	slices.SortStableFunc(ids, func(a, b age.Identity) int {
		an, bn := isNativeForDecrypt(a), isNativeForDecrypt(b)
		switch {
		case an && !bn:
			return -1
		case !an && bn:
			return 1
		}
		return 0
	})
}

func isNativeForDecrypt(id age.Identity) bool {
	if w, ok := id.(*auditIdentity); ok {
		id = w.Identity
	}
	switch id.(type) {
	case *age.X25519Identity, *age.HybridIdentity, *age.ScryptIdentity:
		return true
	}
	return false
}

// isLazyScryptIdentity reports whether id is (or wraps) a
// LazyScryptIdentity, for the passphrase hint in decrypt.
func isLazyScryptIdentity(id age.Identity) bool {
	if w, ok := id.(*auditIdentity); ok {
		id = w.Identity
	}
	_, ok := id.(*LazyScryptIdentity)
	return ok
}

// relativizePath returns name relative to the working directory, so that
// audit records never contain absolute paths or the user's home directory.
// If name can't be relativized (e.g. it's on a different volume), only its
// base name is used.
func relativizePath(name string) string {
	if name == "" || name == "-" {
		return name
	}
	abs, err := filepath.Abs(name)
	if err != nil {
		return filepath.Base(name)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return filepath.Base(name)
	}
	rel, err := filepath.Rel(cwd, abs)
	if err != nil {
		return filepath.Base(name)
	}
	return rel
}
