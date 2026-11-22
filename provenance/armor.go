// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package provenance

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"filippo.io/age/internal/format"
)

const (
	// ArmorHeader marks a text-encapsulated provenance envelope.
	ArmorHeader = "-----BEGIN AGE PROVENANCE FILE-----"
	// ArmorFooter closes a text-encapsulated provenance envelope.
	ArmorFooter = "-----END AGE PROVENANCE FILE-----"
)

// NewArmorWriter wraps dst in PEM-style ASCII armoring of a binary
// envelope. The caller must Close it after writing the full envelope.
func NewArmorWriter(dst io.Writer) io.WriteCloser {
	return &armorWriter{dst: dst, enc: format.NewWrappedBase64Encoder(base64.StdEncoding, dst)}
}

type armorWriter struct {
	started, closed bool
	enc             *format.WrappedBase64Encoder
	dst             io.Writer
}

func (a *armorWriter) Write(p []byte) (int, error) {
	if a.closed {
		return 0, errors.New("provenance: armored writer already closed")
	}
	if !a.started {
		if _, err := io.WriteString(a.dst, ArmorHeader+"\n"); err != nil {
			return 0, err
		}
		a.started = true
	}
	return a.enc.Write(p)
}

func (a *armorWriter) Close() error {
	if a.closed {
		return errors.New("provenance: armored writer already closed")
	}
	a.closed = true
	if !a.started {
		if _, err := io.WriteString(a.dst, ArmorHeader+"\n"); err != nil {
			return err
		}
		a.started = true
	}
	if err := a.enc.Close(); err != nil {
		return err
	}
	footer := ArmorFooter + "\n"
	if !a.enc.LastLineIsEmpty() {
		footer = "\n" + footer
	}
	_, err := io.WriteString(a.dst, footer)
	return err
}

// IsArmored reports whether r's first non-space bytes are a provenance
// armor header. It never consumes more than 1 KiB.
func IsArmored(r *bufio.Reader) bool {
	peek, err := r.Peek(1024)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
		return false
	}
	return bytes.HasPrefix(bytes.TrimSpace(peek), []byte(ArmorHeader))
}

// NewArmorReader decodes an armored provenance envelope, enforcing strict
// base64 and rejecting leading/trailing junk.
func NewArmorReader(r io.Reader) io.Reader {
	return &armorReader{r: bufio.NewReader(r)}
}

type armorReader struct {
	r       *bufio.Reader
	started bool
	unread  []byte
	buf     [format.BytesPerLine]byte
	err     error
}

func (a *armorReader) setErr(err error) error {
	if err != io.EOF {
		err = fmt.Errorf("%w: invalid armor: %v", ErrProofInvalid, err)
	}
	a.err = err
	return err
}

func (a *armorReader) Read(p []byte) (int, error) {
	if len(a.unread) > 0 {
		n := copy(p, a.unread)
		a.unread = a.unread[n:]
		return n, nil
	}
	if a.err != nil {
		return 0, a.err
	}

	getLine := func() ([]byte, error) {
		line, err := a.r.ReadBytes('\n')
		if err == io.EOF && len(line) == 0 {
			return nil, io.ErrUnexpectedEOF
		} else if err != nil && err != io.EOF {
			return nil, err
		}
		line = bytes.TrimSuffix(line, []byte("\n"))
		line = bytes.TrimSuffix(line, []byte("\r"))
		return line, nil
	}

	const maxWhitespace = 1024
	drainTrailing := func() error {
		buf, err := io.ReadAll(io.LimitReader(a.r, maxWhitespace))
		if err != nil {
			return err
		}
		if len(bytes.TrimSpace(buf)) != 0 {
			return errors.New("trailing data after armored file")
		}
		if len(buf) == maxWhitespace {
			return errors.New("too much trailing whitespace")
		}
		return io.EOF
	}

	var removed int
	for !a.started {
		line, err := getLine()
		if err != nil {
			return 0, a.setErr(err)
		}
		if len(bytes.TrimSpace(line)) == 0 {
			removed += len(line) + 1
			if removed > maxWhitespace {
				return 0, a.setErr(errors.New("too much leading whitespace"))
			}
			continue
		}
		if string(line) != ArmorHeader {
			return 0, a.setErr(fmt.Errorf("invalid first line: %q", line))
		}
		a.started = true
	}

	line, err := getLine()
	if err != nil {
		return 0, a.setErr(err)
	}
	if string(line) == ArmorFooter {
		return 0, a.setErr(drainTrailing())
	}
	if len(line) == 0 {
		return 0, a.setErr(errors.New("empty line in armored data"))
	}
	if len(line) > format.ColumnsPerLine {
		return 0, a.setErr(errors.New("column limit exceeded"))
	}
	if bytes.ContainsAny(line, "\n\r") {
		return 0, a.setErr(errors.New("unexpected newline character"))
	}
	a.unread = a.buf[:]
	n, err := base64.StdEncoding.Strict().Decode(a.unread, line)
	if err != nil {
		return 0, a.setErr(err)
	}
	a.unread = a.unread[:n]

	if n < format.BytesPerLine {
		line, err := getLine()
		if err != nil {
			return 0, a.setErr(err)
		}
		if string(line) != ArmorFooter {
			return 0, a.setErr(fmt.Errorf("invalid closing line: %q", line))
		}
		a.setErr(drainTrailing())
	}

	nn := copy(p, a.unread)
	a.unread = a.unread[nn:]
	return nn, nil
}
