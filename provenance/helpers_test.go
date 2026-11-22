// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package provenance

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

func sha256SumBytes(b []byte) []byte { return sha256Sum(b) }

func sshAuthorizedLine(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimRight(string(ssh.MarshalAuthorizedKey(sshPub)), "\n")
}
