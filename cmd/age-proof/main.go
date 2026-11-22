// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// age-proof adds and verifies an accountable provenance layer (the
// age-proof-v1 envelope) around existing age ciphertexts.
package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"filippo.io/age/provenance"
)

// Exit codes keep the legacy age(1) convention (1 for generic failures) and
// add a distinct, stable code for every provenance failure class so that
// automation can tell "no proof", "broken proof", "unknown signer",
// "revoked signer", "expired proof", and "trust list unusable" apart.
const (
	exitGeneric          = 1
	exitTrustList        = 2
	exitProofMissing     = 3
	exitProofInvalid     = 4
	exitSignerUnknown    = 5
	exitSignerRevoked    = 6
	exitProofExpired     = 7
	exitBatchHasFailures = 8
)

var l = log.New(os.Stderr, "", 0)

func printf(format string, v ...any) {
	l.Printf("age-proof: "+format, v...)
}

// errorf exits with the generic age-style code of 1, preserving the
// established CLI convention for non-provenance failures.
func errorf(format string, v ...any) {
	l.Printf("age-proof: error: "+format, v...)
	os.Exit(exitGeneric)
}

func exitFor(err error) int {
	switch {
	case errors.Is(err, provenance.ErrTrustListUnavailable):
		return exitTrustList
	case errors.Is(err, provenance.ErrProofMissing):
		return exitProofMissing
	case errors.Is(err, provenance.ErrProofInvalid):
		return exitProofInvalid
	case errors.Is(err, provenance.ErrSignerUnknown):
		return exitSignerUnknown
	case errors.Is(err, provenance.ErrSignerRevoked):
		return exitSignerRevoked
	case errors.Is(err, provenance.ErrProofExpired):
		return exitProofExpired
	default:
		return exitGeneric
	}
}

// failWith prints err and exits with the stable code for its provenance
// failure class.
func failWith(err error) {
	l.Printf("age-proof: error: %v", err)
	os.Exit(exitFor(err))
}

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(exitGeneric)
	}
	switch os.Args[1] {
	case "-h", "--help", "help":
		usage()
		return
	case "--version", "version":
		fmt.Println("age-proof v1.3.2-provenance")
		return
	case "sign":
		cmdSign(os.Args[2:])
	case "verify":
		cmdVerify(os.Args[2:])
	case "decrypt":
		cmdDecrypt(os.Args[2:])
	case "unwrap":
		cmdUnwrap(os.Args[2:])
	case "keygen":
		cmdKeygen(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "age-proof: unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(exitGeneric)
	}
}

const usageText = `Usage:
    age-proof sign   -k SIGNER [-k SIGNER]... [--armor] [--expires T] [-o OUT] [INPUT...]
    age-proof verify -t TRUSTLIST... [--list] [INPUT...]
    age-proof decrypt -t TRUSTLIST... [-i IDENTITY]... [--require-proof] [-o OUT] [INPUT...]
    age-proof unwrap  [-o OUT] [INPUT]
    age-proof keygen  [-y] [-o OUT] [INPUT]

age-proof wraps an existing age ciphertext in an age-proof-v1 provenance
envelope carrying one or more Ed25519 signatures. The inner age file is
never modified: files without an envelope keep decrypting with plain age.

INPUT may be a file, a directory (processed recursively), or "-" / omitted
for standard input. In directory mode every age file is processed in place,
with proof output written next to its input; a failure on one file never
stops the others.

Options:
    -k, --key PATH           Ed25519 signer key (OpenSSH or PKCS#8 PEM). Repeatable.
    -t, --trustlist PATH     Receiver-maintained trusted signer list. Repeatable.
    -i, --identity PATH      age identity for decrypt. Repeatable.
    -a, --armor              Emit a PEM text envelope instead of binary.
    -o, --output OUT         Output path (single input / stdin only).
        --expires RFC3339    Expiration timestamp embedded in the proof.
        --require-proof      decrypt: reject files that carry no envelope.
        --list               verify: print verified signer fingerprints.
    -y                       keygen: derive the public key of INPUT.

Trust list lines (blank lines and "#" comments ignored):
    ssh-ed25519 AAAA... [label]
    age-proof-1... [label]
    revoked: <key line>
    expires: 2030-01-01T00:00:00Z <key line>
`

func usage() {
	fmt.Fprint(os.Stderr, usageText)
}
