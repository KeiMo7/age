// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// inputTarget is one unit of work: stdin or a regular file discovered from
// the command line / a recursive directory walk.
type inputTarget struct {
	path string // "" means stdin
}

// collectInputs expands positional arguments into work units. Directories
// are walked recursively. A "-" or no argument means stdin.
func collectInputs(args []string) ([]inputTarget, error) {
	if len(args) == 0 || (len(args) == 1 && args[0] == "-") {
		return []inputTarget{{}}, nil
	}
	var targets []inputTarget
	for _, arg := range args {
		info, err := os.Stat(arg)
		if err != nil {
			return nil, fmt.Errorf("failed to stat input %q: %w", arg, err)
		}
		if !info.IsDir() {
			targets = append(targets, inputTarget{path: arg})
			continue
		}
		err = filepath.WalkDir(arg, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.Type().IsRegular() {
				targets = append(targets, inputTarget{path: path})
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("failed to walk directory %q: %w", arg, err)
		}
	}
	if len(targets) == 0 {
		return nil, errors.New("no input files found")
	}
	return targets, nil
}

// openInput opens a target. Stdin is returned as-is (non-seekable); the
// library spools it internally.
func openInput(t inputTarget) (io.ReadCloser, error) {
	if t.path == "" {
		return os.Stdin, nil
	}
	return os.Open(t.path)
}

// armoredAgeSuffixes are stripped, in order, when deriving output names.
var armoredAgeSuffixes = []string{".age.aproof", ".age.proof", ".aproof", ".proof", ".age"}

// proofOutputPath derives the envelope path next to the input.
func proofOutputPath(in string, armored bool) string {
	lower := strings.ToLower(in)
	for _, suffix := range armoredAgeSuffixes {
		if strings.HasSuffix(lower, suffix) {
			base := in[:len(in)-len(suffix)]
			if armored {
				return base + ".age.aproof"
			}
			return base + ".age.proof"
		}
	}
	if armored {
		return in + ".aproof"
	}
	return in + ".proof"
}

// plainOutputPath derives a decrypted path next to the input.
func plainOutputPath(in string) string {
	lower := strings.ToLower(in)
	for _, suffix := range armoredAgeSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return in[:len(in)-len(suffix)]
		}
	}
	return in + ".dec"
}

// createExclusive refuses to overwrite an existing file in batch mode.
func createExclusive(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
}
