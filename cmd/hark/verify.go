package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/DevGurav/hark/internal/bundle"
	"github.com/DevGurav/hark/internal/logfmt"
)

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	quiet := fs.Bool("quiet", false, "print nothing; communicate through the exit status alone")
	pin := fs.String("key", "", "require the tree head to be signed by this hex public key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: hark verify [-quiet] [-key HEX] <bundle>")
	}

	res, err := bundle.Verify(fs.Arg(0))
	if err != nil {
		return err
	}

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
		printVerify(res, *pin != "", pinnedOK)
	}

	switch {
	case res.Status == bundle.StatusBroken:
		os.Exit(1)
	case !pinnedOK:
		os.Exit(1)
	case res.Status == bundle.StatusTruncated:
		// A truncated bundle is a real state, not a verification failure, but a
		// script that expects a complete run should be able to notice. Exit 3
		// keeps it distinguishable from both success and corruption.
		os.Exit(3)
	}
	return nil
}

func printVerify(res *bundle.Result, pinned, pinnedOK bool) {
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

	if res.RekorEntry != "" {
		fmt.Printf("  transparency %s (index %d)\n", res.RekorEntry, res.RekorIndex)
	} else {
		fmt.Println("  transparency not anchored -- integrity only, no non-equivocation")
	}

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
