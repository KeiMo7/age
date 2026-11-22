// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/ed25519"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"filippo.io/age/provenance"
	"golang.org/x/crypto/ssh"
)

func cmdKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var outFlag string
	var convert bool
	fs.StringVar(&outFlag, "o", "", "output `PATH` (default stdout)")
	fs.StringVar(&outFlag, "output", "", "output `PATH` (default stdout)")
	fs.BoolVar(&convert, "y", false, "derive the public key from INPUT")
	if err := fs.Parse(args); err != nil {
		os.Exit(exitGeneric)
	}
	if fs.NArg() > 1 {
		errorf("keygen takes at most one input")
	}

	if convert {
		keygenPublic(fs.Arg(0), outFlag)
		return
	}
	keygenGenerate(outFlag)
}

func keygenGenerate(outFlag string) {
	pub, priv, err := provenance.GenerateSignerKey()
	if err != nil {
		errorf("internal error: %v", err)
	}
	// OpenSSH native format: the key is reusable directly with ssh-keygen
	// and the age-proof -k flag.
	block, err := ssh.MarshalPrivateKey(priv, "age-proof")
	if err != nil {
		errorf("internal error: %v", err)
	}
	pem := pem.EncodeToMemory(block)
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		errorf("internal error: %v", err)
	}
	authorized := ssh.MarshalAuthorizedKey(sshPub)
	native, err := provenance.EncodeNativePublicKey(pub)
	if err != nil {
		errorf("internal error: %v", err)
	}

	out := os.Stdout
	if outFlag != "" {
		f, err := os.OpenFile(outFlag, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			errorf("failed to open output %q: %v", outFlag, err)
		}
		defer f.Close()
		out = f
	}
	fmt.Fprintf(out, "# created: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(out, "# public key: %s\n", native)
	out.Write(pem)

	if outFlag != "" {
		// Public material goes to stderr, never into a pipe that carries
		// the private key.
		fmt.Fprintf(os.Stderr, "Public key: %s", authorized)
		fmt.Fprintf(os.Stderr, "Native key: %s\n", native)
		fmt.Fprintf(os.Stderr, "Fingerprint: %s\n", provenance.KeyFingerprint(pub))
	}
}

func keygenPublic(input, outFlag string) {
	var f *os.File = os.Stdin
	if input != "" && input != "-" {
		opened, err := os.Open(input)
		if err != nil {
			errorf("failed to open input %q: %v", input, err)
		}
		f = opened
		defer f.Close()
	}
	pem, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		errorf("failed to read input: %v", err)
	}
	priv, err := provenance.ParseSignerPrivateKey(pem)
	if err != nil {
		errorf("%v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		errorf("internal error: %v", err)
	}

	out := os.Stdout
	if outFlag != "" {
		created, err := os.OpenFile(outFlag, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			errorf("failed to open output %q: %v", outFlag, err)
		}
		defer created.Close()
		out = created
	}
	out.Write(ssh.MarshalAuthorizedKey(sshPub))
	native, err := provenance.EncodeNativePublicKey(pub)
	if err != nil {
		errorf("internal error: %v", err)
	}
	fmt.Fprintln(out, native)
}
