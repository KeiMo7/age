// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package provenance

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
)

// Detect classifies the first bytes of r. It returns:
//
//   - true, true  for an armored provenance envelope,
//   - true, false for a binary provenance envelope,
//   - false, false for anything else (including legacy age files).
//
// The returned reader must be used in place of r: detection may have
// buffered bytes.
func Detect(r io.Reader) (isEnvelope, isArmored bool, rr io.Reader, err error) {
	br := bufio.NewReader(r)
	peek, perr := br.Peek(1024)
	if perr != nil && !errors.Is(perr, io.EOF) && !errors.Is(perr, bufio.ErrBufferFull) {
		return false, false, br, perr
	}
	trimmed := bytes.TrimSpace(peek)
	if bytes.HasPrefix(trimmed, []byte(ArmorHeader)) {
		return true, true, br, nil
	}
	if bytes.HasPrefix(peek, []byte(intro)) {
		return true, false, br, nil
	}
	return false, false, br, nil
}

// Unwrap strips a provenance envelope without verifying it and writes the
// exact inner age ciphertext to dst. It is intended only for interop with
// readers that don't understand the layer; security-sensitive callers must
// use [Open] instead.
func Unwrap(r io.Reader, dst io.Writer) error {
	isEnvelope, isArmored, rr, err := Detect(r)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProofInvalid, err)
	}
	if !isEnvelope {
		return fmt.Errorf("%w: input is not an age-proof-v1 envelope", ErrProofMissing)
	}
	if isArmored {
		rr = NewArmorReader(rr)
	}
	br := bufio.NewReader(rr)
	env, err := parseHeader(br)
	if err != nil {
		return err
	}
	n, err := io.CopyBuffer(dst, io.LimitReader(br, env.InnerSize), make([]byte, copyBufferSize))
	if err != nil {
		return fmt.Errorf("provenance: failed to extract inner ciphertext: %w", err)
	}
	if n != env.InnerSize {
		return fmt.Errorf("%w: truncated inner payload", ErrProofInvalid)
	}
	extra := make([]byte, 1)
	if m, _ := br.Read(extra); m != 0 {
		return fmt.Errorf("%w: trailing data after envelope", ErrProofInvalid)
	}
	return nil
}
