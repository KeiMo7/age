// Copyright 2026 The age Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"

	"filippo.io/age/provenance"
)

func cmdVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var trustFlags multiPath
	var list bool
	fs.Var(&trustFlags, "t", "trust list `PATH` (repeatable)")
	fs.Var(&trustFlags, "trustlist", "trust list `PATH` (repeatable)")
	fs.BoolVar(&list, "list", false, "print verified signer fingerprints")
	if err := fs.Parse(args); err != nil {
		os.Exit(exitGeneric)
	}
	if len(trustFlags) == 0 {
		errorf("verify requires at least one -t/--trustlist")
	}
	trust, err := loadMergedTrust(trustFlags)
	if err != nil {
		failWith(err)
	}

	targets, err := collectInputs(fs.Args())
	if err != nil {
		errorf("%v", err)
	}
	batch := len(targets) > 1

	var failures int
	for _, t := range targets {
		res, verr := verifyOne(t, trust)
		label := t.path
		if label == "" {
			label = "stdin"
		}
		if verr != nil {
			failures++
			printf("verify: %s: %v", label, verr)
			if !batch {
				failWith(verr)
			}
			continue
		}
		if list {
			for _, s := range res.Signers {
				labelPart := ""
				if s.Label != "" {
					labelPart = " " + s.Label
				}
				printf("verify: %s: ok signer %x%s", label, s.KeyID, labelPart)
			}
		} else {
			printf("verify: %s: ok (%d valid signature%s)", label,
				len(res.Signers), plural(len(res.Signers)))
		}
	}
	if batch && failures > 0 {
		printf("verify: %d of %d inputs failed", failures, len(targets))
		os.Exit(exitBatchHasFailures)
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func verifyOne(t inputTarget, trust []*provenance.TrustEntry) (*provenance.VerifyResult, error) {
	in, err := openInput(t)
	if err != nil {
		return nil, err
	}
	defer in.Close()

	isEnv, isArmored, rr, err := provenance.Detect(in)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", provenance.ErrProofInvalid, err)
	}
	if !isEnv {
		return nil, fmt.Errorf("%w: %s", provenance.ErrProofMissing, "no provenance envelope")
	}
	if isArmored {
		rr = provenance.NewArmorReader(rr)
	}
	inner, res, err := provenance.Open(rr, provenance.VerifyParams{Trust: trust})
	if err != nil {
		return nil, err
	}
	defer inner.Close()
	// Drain the inner stream so digest/length checks fully run; nothing is
	// written anywhere.
	if err := drain(inner); err != nil {
		return nil, err
	}
	return res, nil
}

func loadMergedTrust(paths []string) ([]*provenance.TrustEntry, error) {
	var merged []*provenance.TrustEntry
	seen := make(map[string]bool)
	for _, path := range paths {
		entries, err := provenance.LoadTrustListFile(path)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			id := string(e.KeyID)
			if seen[id] {
				continue
			}
			seen[id] = true
			merged = append(merged, e)
		}
	}
	if len(merged) == 0 {
		return nil, fmt.Errorf("%w: trust lists contain no entries", provenance.ErrTrustListUnavailable)
	}
	return merged, nil
}
