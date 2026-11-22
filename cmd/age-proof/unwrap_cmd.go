// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"filippo.io/age/provenance"
)

func cmdUnwrap(args []string) {
	fs := flag.NewFlagSet("unwrap", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var outFlag string
	fs.StringVar(&outFlag, "o", "", "output `PATH` (default stdout)")
	fs.StringVar(&outFlag, "output", "", "output `PATH` (default stdout)")
	if err := fs.Parse(args); err != nil {
		os.Exit(exitGeneric)
	}
	if fs.NArg() > 1 {
		errorf("unwrap takes at most one input")
	}

	var in io.ReadCloser = os.Stdin
	if name := fs.Arg(0); name != "" && name != "-" {
		f, err := os.Open(name)
		if err != nil {
			errorf("failed to open input %q: %v", name, err)
		}
		in = f
	}
	defer in.Close()

	var out io.WriteCloser = nopWriteCloser{os.Stdout}
	var outPath string
	if outFlag != "" && outFlag != "-" {
		f, err := createExclusive(outFlag)
		if err != nil {
			errorf("failed to open output %q: %v", outFlag, err)
		}
		out, outPath = f, outFlag
	}
	defer func() {
		if err := out.Close(); err != nil {
			errorf("failed to close output: %v", err)
		}
	}()

	if err := provenance.Unwrap(in, out); err != nil {
		if outPath != "" {
			os.Remove(outPath)
		}
		failWith(err)
	}
	if outPath != "" {
		fmt.Fprintf(os.Stderr, "age-proof: unwrapped inner ciphertext -> %s\n", outPath)
	}
}
