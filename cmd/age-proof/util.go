// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"io"

	"filippo.io/age/armor"
)

// multiPath is a repeatable string flag (-k, -t, -i).
type multiPath []string

func (m *multiPath) String() string { return "" }

func (m *multiPath) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// newPeekReader returns a bufio.Reader suitable for Peek-based detection.
func newPeekReader(r io.Reader) *bufio.Reader {
	if br, ok := r.(*bufio.Reader); ok {
		return br
	}
	return bufio.NewReader(r)
}

// looksLikeArmoredAge reports whether the buffered prefix is an armored age
// file (PEM type "AGE ENCRYPTED FILE"), distinct from a provenance armor.
func looksLikeArmoredAge(br *bufio.Reader) bool {
	peek, err := br.Peek(1024)
	if err != nil && err != io.EOF && err != bufio.ErrBufferFull {
		return false
	}
	return bytes.HasPrefix(bytes.TrimSpace(peek), []byte(armor.Header))
}

// ageArmorNewReader de-armors a legacy armored age file.
func ageArmorNewReader(r io.Reader) io.Reader {
	return armor.NewReader(r)
}
