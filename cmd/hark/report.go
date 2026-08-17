package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/DevGurav/hark/internal/bundle"
	"github.com/DevGurav/hark/internal/rekor"
	"github.com/DevGurav/hark/internal/report"
)

// hark report renders a bundle as one static HTML file.
//
// It is a way to read a run, not a way to check one. The header repeats what
// `hark verify` found at the moment the file was written, and the page says so:
// a reviewer who trusts a rendered page instead of running the verifier has
// been given a picture of a verification, which is not the same thing.

func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	out := fs.String("o", "", "write here (default: <bundle>.html)")
	maxBody := fs.Int("max-body", 0, "bytes of any one body to render (default 4096)")
	offline := fs.Bool("offline", false, "do not ask the transparency log about the anchor")
	rekorURL := fs.String("rekor", rekor.PublicLog, "transparency log to check inclusion against")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: hark report [-o FILE] [-offline] <bundle>")
	}
	path := fs.Arg(0)

	// The anchor is checked here rather than in the report package: a static
	// file that reached out to a log while being rendered would be one more
	// thing to explain, and the page must never make a request of its own.
	res, err := bundle.Verify(path)
	if err != nil {
		return err
	}
	anchor := checkAnchor(res, *offline, *rekorURL)

	target := *out
	if target == "" {
		target = path + ".html"
	}
	f, err := os.Create(target)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	if err := report.Render(w, path, report.Options{
		MaxBody:   *maxBody,
		Anchor:    anchor.line,
		Summarise: summarise,
		Verified:  res,
	}); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}

	info, err := f.Stat()
	if err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d events, %.1f KiB)\n", target, res.LeafCount, float64(info.Size())/1024)
	return nil
}
