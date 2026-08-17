package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/DevGurav/hark/internal/bundle"
	"github.com/DevGurav/hark/internal/logfmt"
	"github.com/DevGurav/hark/internal/rekor"
)

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	quiet := fs.Bool("quiet", false, "print nothing; communicate through the exit status alone")
	pin := fs.String("key", "", "require the tree head to be signed by this hex public key")
	offline := fs.Bool("offline", false, "skip the transparency log; check only what is in the file")
	rekorURL := fs.String("rekor", rekor.PublicLog, "transparency log to check inclusion against")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: hark verify [-quiet] [-offline] [-key HEX] <bundle>")
	}

	res, err := bundle.Verify(fs.Arg(0))
	if err != nil {
		return err
	}

	anchor := checkAnchor(res, *offline, *rekorURL)

	// A pinned key turns the signature check from "someone signed this" into
	// "the party I expect signed this". Without it a valid signature says very
	// little, since the key travels inside the bundle it authenticates.
	pinnedOK := true
	if *pin != "" {
		want, err := hex.DecodeString(*pin)
		if err != nil {
			return fmt.Errorf("-key: %w", err)
		}
		pinnedOK = res.SignatureOK && hex.EncodeToString(res.PublicKey) == hex.EncodeToString(want)
	}

	if !*quiet {
		printVerify(res, *pin != "", pinnedOK, anchor)
	}

	switch {
	case res.Status == bundle.StatusBroken:
		os.Exit(1)
	case !pinnedOK:
		os.Exit(1)
	case anchor.rejected:
		// The bundle names an entry the log does not vouch for. That is a claim
		// the bundle makes and fails, so it fails verification -- unlike a log
		// that could not be reached, which establishes nothing either way.
		os.Exit(1)
	case res.Status == bundle.StatusTruncated:
		// A truncated bundle is a real state, not a verification failure, but a
		// script that expects a complete run should be able to notice. Exit 3
		// keeps it distinguishable from both success and corruption.
		os.Exit(3)
	}
	return nil
}

// anchorCheck is what the transparency log had to say, if it was asked.
type anchorCheck struct {
	line     string
	rejected bool
}

// checkAnchor fetches the inclusion proof for a bundle that carries an entry.
//
// Three outcomes, deliberately distinct, because collapsing them is how a
// verifier ends up overstating what it knows:
//
//	inclusion verified   the commitment is public and cannot now be changed
//	REJECTED             the log does not vouch for what the bundle claims
//	unreachable          nothing established either way; the local checks stand
func checkAnchor(res *bundle.Result, offline bool, logURL string) anchorCheck {
	switch {
	case res.RekorEntry == "":
		return anchorCheck{line: "not anchored -- integrity only, no non-equivocation"}
	case offline:
		return anchorCheck{line: fmt.Sprintf("%s (index %d), not checked (-offline)", res.RekorEntry, res.RekorIndex)}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	entry, err := rekor.New(logURL).Fetch(ctx, res.RekorEntry)
	if errors.Is(err, rekor.ErrNotFound) {
		return anchorCheck{rejected: true, line: fmt.Sprintf("REJECTED -- %s holds no entry %s", logURL, res.RekorEntry)}
	}
	if err != nil {
		return anchorCheck{line: fmt.Sprintf("%s (index %d), log unreachable: %v", res.RekorEntry, res.RekorIndex, err)}
	}

	// The entry has to be the log's record of *this* tree head. Without that
	// check, "the log holds entry X" and "entry X is this run" are two separate
	// claims with nothing joining them.
	if res.STH == nil {
		return anchorCheck{rejected: true, line: "REJECTED -- anchored but unsigned: nothing ties the entry to this bundle"}
	}
	if err := entry.Covers(res.STH); err != nil {
		return anchorCheck{rejected: true, line: "REJECTED -- " + err.Error()}
	}
	if err := entry.VerifyInclusion(); err != nil {
		return anchorCheck{rejected: true, line: "REJECTED -- " + err.Error()}
	}

	return anchorCheck{line: fmt.Sprintf("inclusion verified, index %d of %d (%s)",
		entry.LogIndex, entry.Proof.TreeSize, logURL)}
}

func printVerify(res *bundle.Result, pinned, pinnedOK bool, anchor anchorCheck) {
	// A pin failure is a verification failure even though every internal check
	// passed, so it has to change the headline. Printing VERIFIED above a line
	// that says the key was wrong is how a reader ends up trusting the wrong
	// bundle.
	switch {
	case pinned && !pinnedOK:
		fmt.Println("REJECTED -- signed by an unexpected key")
	case res.Status == bundle.StatusSealed:
		fmt.Println("VERIFIED")
	case res.Status == bundle.StatusTruncated:
		fmt.Println("TRUNCATED -- verified prefix only")
	case res.Status == bundle.StatusBroken:
		fmt.Println("BROKEN")
	}

	fmt.Printf("  run          %s\n", res.RunID)
	if res.Status == bundle.StatusSealed {
		fmt.Printf("  events       %d\n", res.LeafCount)
	} else {
		fmt.Printf("  events       %d verified\n", res.LeafCount)
	}
	fmt.Printf("  merkle root  %x\n", res.Root)
	fmt.Printf("  chain head   %x\n", res.FinalChain)

	switch {
	case !res.Signed:
		fmt.Println("  signature    absent")
	case res.SignatureOK:
		fmt.Printf("  signature    ok, key %x\n", res.PublicKey)
	default:
		fmt.Println("  signature    FAILED")
	}
	if pinned {
		if pinnedOK {
			fmt.Println("  pinned key   matches")
		} else {
			fmt.Println("  pinned key   MISMATCH")
		}
	}

	fmt.Printf("  transparency %s\n", anchor.line)

	if res.Problem != "" {
		if res.FirstBadSeq >= 0 {
			fmt.Printf("  first fault  seq %d: %s\n", res.FirstBadSeq, res.Problem)
		} else {
			fmt.Printf("  note         %s\n", res.Problem)
		}
	}

	if len(res.KindCounts) > 0 {
		kinds := make([]logfmt.Kind, 0, len(res.KindCounts))
		for k := range res.KindCounts {
			kinds = append(kinds, k)
		}
		sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
		fmt.Println("  events by kind")
		for _, k := range kinds {
			fmt.Printf("    %-18s %d\n", k, res.KindCounts[k])
		}
	}
}
