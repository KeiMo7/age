// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestRelativizePath(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()

	// An absolute path inside the working directory becomes relative.
	inside := filepath.Join(cwd, "sub", "file.age")
	if got := relativizePath(inside); got != filepath.Join("sub", "file.age") {
		t.Errorf("relativizePath(%q) = %q, want %q", inside, got, filepath.Join("sub", "file.age"))
	}

	// An absolute path outside the working directory stays relative and
	// doesn't leak the home directory.
	outside := filepath.Join(filepath.Dir(cwd), "outside.age")
	got := relativizePath(outside)
	if filepath.IsAbs(got) {
		t.Errorf("relativizePath(%q) = %q, still absolute", outside, got)
	}
	if home != "" && strings.HasPrefix(got, home) {
		t.Errorf("relativizePath(%q) = %q, contains home directory", outside, got)
	}

	if got := relativizePath("-"); got != "-" {
		t.Errorf("relativizePath(\"-\") = %q, want \"-\"", got)
	}
}

func TestAuditLogContents(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	a := newAuditor(logPath)
	if a == nil {
		t.Fatal("newAuditor returned nil")
	}
	a.target = "data.age"

	// Simulate a failed attempt with a wrapped identity.
	w := a.wrapIdentity(id, filepath.Join(dir, "keys.txt"))
	if _, err := w.Unwrap([]*age.Stanza{{Type: "scrypt"}}); err == nil {
		t.Fatal("expected Unwrap to fail")
	}
	a.recordFileOutcome("failure", failureMissingRecipient)
	a.close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	log := string(data)

	// The log must not contain any secret key material or anything that
	// could be used to reconstruct it.
	if strings.Contains(log, "AGE-SECRET-KEY") || strings.Contains(log, id.String()) {
		t.Error("audit log contains secret key material")
	}
	// The identity is recorded by its public recipient encoding.
	if !strings.Contains(log, id.Recipient().String()) {
		t.Error("audit log does not contain the public recipient")
	}
	// Paths are relativized: the absolute directory of the identity file
	// must not appear.
	if strings.Contains(log, dir) {
		t.Error("audit log contains an absolute path")
	}

	// Every record carries the schema version and parses as expected.
	lines := strings.Split(strings.TrimSpace(log), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d records, want 2", len(lines))
	}
	var r auditRecord
	if err := json.Unmarshal([]byte(lines[0]), &r); err != nil {
		t.Fatal(err)
	}
	if r.Version != auditRecordVersion {
		t.Errorf("record version = %d, want %d", r.Version, auditRecordVersion)
	}
	if r.Kind != "identity" || r.Result != "failure" || r.Failure != failureIdentityMismatch {
		t.Errorf("unexpected identity record: %+v", r)
	}
	if err := json.Unmarshal([]byte(lines[1]), &r); err != nil {
		t.Fatal(err)
	}
	if r.Kind != "file" || r.Result != "failure" || r.Failure != failureMissingRecipient {
		t.Errorf("unexpected file record: %+v", r)
	}
}

func TestNewAuditorUnwritable(t *testing.T) {
	// A missing directory can't be created by newAuditor: it must warn
	// and return nil, leaving decryption unaffected.
	if a := newAuditor(filepath.Join(t.TempDir(), "no", "such", "dir", "log.jsonl")); a != nil {
		t.Error("newAuditor with unwritable path returned non-nil auditor")
	}
}

func TestAuditIdentityLabel(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	label, typ := auditIdentityLabel(id, "keys.txt")
	if label != id.Recipient().String() || typ != "x25519" {
		t.Errorf("auditIdentityLabel = %q, %q", label, typ)
	}
	if strings.Contains(label, id.String()) {
		t.Error("label contains secret key material")
	}

	label, typ = auditIdentityLabel(&LazyScryptIdentity{}, "")
	if label != "scrypt" || typ != "scrypt" {
		t.Errorf("auditIdentityLabel = %q, %q", label, typ)
	}
}
