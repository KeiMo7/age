// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"io"

	"filippo.io/age/internal/term"
)

// readSecret reads a line without echo. It is split out so tests can stub
// it; the returned secret is never logged.
var readSecret = func(prompt string) ([]byte, error) {
	return term.ReadSecret(prompt)
}

// drain consumes r fully. Verification finalizes only once the full
// verified stream has been consumed by callers that need it drained.
func drain(r io.Reader) error {
	buf := make([]byte, copyBufSize)
	for {
		n, err := r.Read(buf)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		_ = n
	}
}
