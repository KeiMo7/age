// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"filippo.io/age/armor"
	"filippo.io/age/provenance"
)

func cmdSign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var keyFlags multiPath
	var outFlag string
	var armored bool
	var expires string
	fs.Var(&keyFlags, "k", "signer key `PATH` (repeatable)")
	fs.Var(&keyFlags, "key", "signer key `PATH` (repeatable)")
	fs.StringVar(&outFlag, "o", "", "output `PATH` (single input only)")
	fs.StringVar(&outFlag, "output", "", "output `PATH` (single input only)")
	fs.BoolVar(&armored, "a", false, "emit PEM text envelope")
	fs.BoolVar(&armored, "armor", false, "emit PEM text envelope")
	fs.StringVar(&expires, "expires", "", "RFC3339 expiration timestamp")
	if err := fs.Parse(args); err != nil {
		os.Exit(exitGeneric)
	}
	if len(keyFlags) == 0 {
		errorf("sign requires at least one -k/--key signer key")
	}
	var expiry time.Time
	if expires != "" {
		t, err := time.Parse(time.RFC3339, expires)
		if err != nil {
			errorf("invalid --expires timestamp: %v", err)
		}
		expiry = t
	}

	keys := make([]ed25519.PrivateKey, 0, len(keyFlags))
	for _, path := range keyFlags {
		pem, err := os.ReadFile(path)
		if err != nil {
			errorf("failed to read signer key %q: %v", path, err)
		}
		key, err := provenance.ParseSignerPrivateKey(pem)
		if err != nil {
			errorf("%v", err)
		}
		keys = append(keys, key)
	}

	targets, err := collectInputs(fs.Args())
	if err != nil {
		errorf("%v", err)
	}
	batch := len(targets) > 1
	if batch && outFlag != "" {
		errorf("-o/--output can only be used with a single input")
	}

	params := provenance.SignParams{
		SecretKeys: keys,
		Created:    time.Now().UTC(),
		Expires:    expiry,
	}

	var failures int
	for _, t := range targets {
		if err := signOne(t, params, armored, outFlag, batch); err != nil {
			failures++
			label := t.path
			if label == "" {
				label = "stdin"
			}
			printf("sign: %s: %v", label, err)
			if !batch {
				failWith(err)
			}
		}
	}
	if batch && failures > 0 {
		printf("sign: %d of %d inputs failed", failures, len(targets))
		os.Exit(exitBatchHasFailures)
	}
}

func signOne(t inputTarget, params provenance.SignParams, armored bool, outFlag string, batch bool) (err error) {
	in, err := openInput(t)
	if err != nil {
		return err
	}
	defer in.Close()

	// Accept both binary and armored age files; de-armor first so the
	// signed inner bytes are always the canonical binary age ciphertext.
	// Reject provenance envelopes (no nested signing) and plaintext.
	rr, err := dearmorAgeInput(in)
	if err != nil {
		return err
	}

	var out io.WriteCloser
	var outPath string
	if t.path == "" || outFlag != "" {
		switch {
		case outFlag != "" && outFlag != "-":
			f, ferr := createExclusive(outFlag)
			if ferr != nil {
				return fmt.Errorf("failed to open output %q: %w", outFlag, ferr)
			}
			out, outPath = f, outFlag
		default:
			out = nopWriteCloser{os.Stdout}
		}
	} else {
		outPath = proofOutputPath(t.path, armored)
		f, ferr := createExclusive(outPath)
		if ferr != nil {
			return fmt.Errorf("failed to open output %q: %w", outPath, ferr)
		}
		out = f
	}
	defer func() {
		if cerr := out.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close output: %w", cerr)
		}
		// On failure remove a half-written file output, never leaving
		// partial artifacts behind.
		if err != nil && outPath != "" {
			os.Remove(outPath)
		}
	}()

	var dst io.Writer = out
	if armored {
		a := provenance.NewArmorWriter(out)
		defer func() {
			if aerr := a.Close(); aerr != nil && err == nil {
				err = aerr
			}
		}()
		dst = a
	}
	if err = provenance.Sign(dst, rr, params); err != nil {
		return err
	}
	if t.path != "" && (outFlag != "" || batch || outPath != "") {
		printf("signed %s -> %s", t.path, outPath)
	}
	return nil
}

// dearmorAgeInput ensures the signing input is a binary age ciphertext.
// Armored age is de-armored; anything that is not age (including
// provenance envelopes and arbitrary plaintext) is rejected.
func dearmorAgeInput(in io.Reader) (io.Reader, error) {
	br := newPeekReader(in)
	head, err := br.Peek(len("age-encryption.org/v1\n"))
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("failed to read input: %w", err)
	}
	switch {
	case string(head) == "age-encryption.org/v1\n":
		return br, nil
	case looksLikeArmoredAge(br):
		return armor.NewReader(br), nil
	default:
		// Distinguish plaintext from an envelope for a clearer message.
		if isEnv, _, _, _ := provenance.Detect(br); isEnv {
			return nil, fmt.Errorf("%w: input already carries a provenance envelope", provenance.ErrProofInvalid)
		}
		return nil, provenance.ErrNotEncrypted
	}
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }
