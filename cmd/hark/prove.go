package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/DevGurav/hark/internal/bundle"
	"github.com/DevGurav/hark/internal/hashchain"
	"github.com/DevGurav/hark/internal/mmr"
)

// proofDoc is the shareable form of an inclusion proof.
//
// The point of emitting this separately from the bundle is size: proving that
// one event occurred costs a few hundred bytes and log2(N) hashes, where sending
// the bundle itself could cost hundreds of megabytes. An auditor who already
// trusts a root can check a single event without ever seeing the rest of the run
// -- which also means the rest of the run stays private.
type proofDoc struct {
	Run        string   `json:"run"`
	Seq        uint64   `json:"seq"`
	LeafHash   string   `json:"leaf_hash"`
	Root       string   `json:"root"`
	LeafCount  uint64   `json:"leaf_count"`
	Siblings   []string `json:"siblings"`
	LeftPeaks  []string `json:"left_peaks"`
	RightPeaks []string `json:"right_peaks"`
}

func cmdProve(args []string) error {
	fs := flag.NewFlagSet("prove", flag.ExitOnError)
	seq := fs.Uint64("seq", 0, "sequence number of the event to prove")
	out := fs.String("out", "", "write the proof here instead of stdout")
	check := fs.String("check", "", "verify this proof file instead of generating one")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *check != "" {
		return checkProof(*check)
	}
	if fs.NArg() != 1 {
		return errors.New("usage: hark prove -seq N [-out FILE] <bundle>  |  hark prove -check FILE")
	}

	p, leaf, root, err := bundle.Prove(fs.Arg(0), *seq)
	if err != nil {
		return err
	}

	r, err := bundle.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	runID := r.Header().RunID
	r.Close()

	doc := proofDoc{
		Run:       runID,
		Seq:       *seq,
		LeafHash:  fmt.Sprintf("%x", leaf),
		Root:      fmt.Sprintf("%x", root),
		LeafCount: p.LeafCount,
	}
	for _, h := range p.Siblings {
		doc.Siblings = append(doc.Siblings, fmt.Sprintf("%x", h))
	}
	for _, h := range p.Left {
		doc.LeftPeaks = append(doc.LeftPeaks, fmt.Sprintf("%x", h))
	}
	for _, h := range p.Right {
		doc.RightPeaks = append(doc.RightPeaks, fmt.Sprintf("%x", h))
	}

	body, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')

	if *out == "" {
		_, err = os.Stdout.Write(body)
		return err
	}
	return os.WriteFile(*out, body, 0o644)
}

func checkProof(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc proofDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}

	root, err := parseHash(doc.Root)
	if err != nil {
		return fmt.Errorf("root: %w", err)
	}
	leaf, err := parseHash(doc.LeafHash)
	if err != nil {
		return fmt.Errorf("leaf_hash: %w", err)
	}

	p := &mmr.Proof{LeafIndex: doc.Seq, LeafCount: doc.LeafCount}
	for _, s := range doc.Siblings {
		h, err := parseHash(s)
		if err != nil {
			return fmt.Errorf("siblings: %w", err)
		}
		p.Siblings = append(p.Siblings, h)
	}
	for _, s := range doc.LeftPeaks {
		h, err := parseHash(s)
		if err != nil {
			return fmt.Errorf("left_peaks: %w", err)
		}
		p.Left = append(p.Left, h)
	}
	for _, s := range doc.RightPeaks {
		h, err := parseHash(s)
		if err != nil {
			return fmt.Errorf("right_peaks: %w", err)
		}
		p.Right = append(p.Right, h)
	}

	if !mmr.Verify(root, leaf, p) {
		fmt.Println("PROOF INVALID")
		os.Exit(1)
	}
	fmt.Printf("PROOF OK\n  run    %s\n  seq    %d of %d\n  root   %s\n", doc.Run, doc.Seq, doc.LeafCount, doc.Root)
	return nil
}

func parseHash(s string) (hashchain.Hash, error) {
	var h hashchain.Hash
	if len(s) != hashchain.Size*2 {
		return h, fmt.Errorf("expected %d hex characters, got %d", hashchain.Size*2, len(s))
	}
	for i := 0; i < hashchain.Size; i++ {
		var b byte
		if _, err := fmt.Sscanf(s[i*2:i*2+2], "%02x", &b); err != nil {
			return h, err
		}
		h[i] = b
	}
	return h, nil
}
