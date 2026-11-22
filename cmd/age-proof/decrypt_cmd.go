// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
	"filippo.io/age/provenance"
)

func cmdDecrypt(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var trustFlags, identityFlags multiPath
	var outFlag string
	var requireProof bool
	fs.Var(&trustFlags, "t", "trust list `PATH` (repeatable)")
	fs.Var(&trustFlags, "trustlist", "trust list `PATH` (repeatable)")
	fs.Var(&identityFlags, "i", "age identity `PATH` (repeatable)")
	fs.Var(&identityFlags, "identity", "age identity `PATH` (repeatable)")
	fs.StringVar(&outFlag, "o", "", "output `PATH` (single input only)")
	fs.StringVar(&outFlag, "output", "", "output `PATH` (single input only)")
	fs.BoolVar(&requireProof, "require-proof", false, "reject files without a provenance envelope")
	if err := fs.Parse(args); err != nil {
		os.Exit(exitGeneric)
	}

	trust, trustErr := loadMergedTrust(trustFlags)
	if trustErr != nil && len(trustFlags) > 0 {
		// A trust list was requested but unusable: hard failure, never a
		// silent downgrade.
		failWith(trustErr)
	}

	targets, err := collectInputs(fs.Args())
	if err != nil {
		errorf("%v", err)
	}
	batch := len(targets) > 1
	if batch && outFlag != "" {
		errorf("-o/--output can only be used with a single input")
	}

	identities, idErr := loadDecryptIdentities(identityFlags)
	if idErr != nil {
		errorf("%v", idErr)
	}

	var failures int
	for _, t := range targets {
		if derr := decryptOne(t, identities, trust, requireProof, outFlag, batch); derr != nil {
			failures++
			label := t.path
			if label == "" {
				label = "stdin"
			}
			printf("decrypt: %s: %v", label, derr)
			if !batch {
				// Provenance failures keep their stable codes; age
				// decryption failures use the generic code.
				failWith(derr)
			}
		}
	}
	if batch && failures > 0 {
		printf("decrypt: %d of %d inputs failed", failures, len(targets))
		os.Exit(exitBatchHasFailures)
	}
}

func decryptOne(t inputTarget, identities []age.Identity, trust []*provenance.TrustEntry,
	requireProof bool, outFlag string, batch bool) (err error) {

	in, err := openInput(t)
	if err != nil {
		return err
	}
	defer in.Close()

	isEnv, isArmored, rr, err := provenance.Detect(in)
	if err != nil {
		return fmt.Errorf("%w: %v", provenance.ErrProofInvalid, err)
	}

	var ciphertext io.Reader = rr
	var verified *provenance.VerifyResult
	var proofCloser io.Closer
	if isEnv {
		if len(trust) == 0 {
			// An envelope without a trust list cannot be authenticated:
			// refuse rather than silently skipping verification.
			return fmt.Errorf("%w: envelope present but no trust list provided", provenance.ErrTrustListUnavailable)
		}
		if isArmored {
			rr = provenance.NewArmorReader(rr)
			ciphertext = rr
		}
		inner, res, verr := provenance.Open(rr, provenance.VerifyParams{Trust: trust})
		if verr != nil {
			return verr
		}
		proofCloser = inner
		ciphertext = inner
		verified = res
	} else if requireProof {
		return fmt.Errorf("%w: --require-proof set but input has no envelope", provenance.ErrProofMissing)
	} else if br := newPeekReader(rr); looksLikeArmoredAge(br) {
		// Legacy armored age file without an envelope: preserve stock age
		// behavior by de-armoring automatically.
		ciphertext = ageArmorNewReader(br)
	}
	if proofCloser != nil {
		defer proofCloser.Close()
	}

	// The output file is created lazily, only after every provenance check
	// has passed, so a rejected envelope can never leave plaintext or a
	// half-written file behind.
	var out io.WriteCloser
	var outPath string
	if t.path == "" || outFlag != "" {
		if outFlag != "" && outFlag != "-" {
			f, ferr := createExclusive(outFlag)
			if ferr != nil {
				return fmt.Errorf("failed to open output %q: %w", outFlag, ferr)
			}
			out, outPath = f, outFlag
		} else {
			out = nopWriteCloser{os.Stdout}
		}
	} else {
		outPath = plainOutputPath(t.path)
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
		if err != nil && outPath != "" {
			os.Remove(outPath)
		}
	}()

	r, err := age.Decrypt(ciphertext, identities...)
	if err != nil {
		return err
	}
	if _, err := io.CopyBuffer(out, r, make([]byte, copyBufSize)); err != nil {
		return err
	}

	label := t.path
	if label == "" {
		label = "stdin"
	}
	switch {
	case verified != nil:
		printf("decrypt: %s: ok (%d verified signature%s)", label,
			len(verified.Signers), plural(len(verified.Signers)))
	default:
		printf("decrypt: %s: ok (no provenance envelope; legacy file)", label)
	}
	return nil
}

const copyBufSize = 32 << 10

// loadDecryptIdentities parses age identity files. With none given, the
// age passphrase identity is used, matching plain age behavior.
func loadDecryptIdentities(paths []string) ([]age.Identity, error) {
	if len(paths) == 0 {
		return []age.Identity{&passIdentity{}}, nil
	}
	var ids []age.Identity
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("failed to open identity %q: %w", path, err)
		}
		parsed, err := age.ParseIdentities(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("reading identity %q: %w", path, err)
		}
		ids = append(ids, parsed...)
	}
	// Mirror age: with explicit identities, a passphrase-encrypted file
	// gets a clear hint instead of a silent hang.
	ids = append(ids, rejectScryptIdentity{})
	return ids, nil
}

// passIdentity prompts on the terminal for scrypt-encrypted files, keeping
// the passphrase out of logs and error strings.
type passIdentity struct{}

func (passIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if len(stanzas) != 1 || stanzas[0].Type != "scrypt" {
		return nil, age.ErrIncorrectIdentity
	}
	pass, err := readSecret("Enter passphrase:")
	if err != nil {
		return nil, fmt.Errorf("could not read passphrase: %w", err)
	}
	id, err := age.NewScryptIdentity(string(pass))
	if err != nil {
		return nil, err
	}
	return id.Unwrap(stanzas)
}

type rejectScryptIdentity struct{}

func (rejectScryptIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if len(stanzas) != 1 || stanzas[0].Type != "scrypt" {
		return nil, age.ErrIncorrectIdentity
	}
	return nil, errors.New("file is passphrase-encrypted; decrypt without -i/--identity to be prompted")
}
