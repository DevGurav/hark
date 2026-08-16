// Command hark records, replays and verifies AI agent runs.
//
// This binary currently implements the bundle half of the system: creating,
// inspecting, verifying and proving inclusion in .hark files. The recording and
// replay halves land in W2 and W3 -- see docs/roadmap.md.
package main

import (
	"fmt"
	"os"

	"github.com/DevGurav/hark/internal/launcher"
)

// Version is the recorder identity stamped into every bundle. Bundles written by
// different versions must remain verifiable, so this is recorded rather than
// enforced.
const Version = "hark 0.1.0-dev"

func main() {
	// The launcher re-executes this binary to build the agent's containment on a
	// locked thread before exec. That branch must be taken before anything else
	// happens -- it is not a subcommand, it is a different process role, and the
	// child must not touch flags, logging or anything with global state.
	if launcher.IsInit(os.Args) {
		if err := launcher.Init(); err != nil {
			fmt.Fprintln(os.Stderr, "hark init:", err)
			os.Exit(126)
		}
		// Unreachable: Init ends in execve.
		os.Exit(127)
	}

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "inspect":
		err = cmdInspect(os.Args[2:])
	case "prove":
		err = cmdProve(os.Args[2:])
	case "keygen":
		err = cmdKeygen(os.Args[2:])
	case "synth":
		err = cmdSynth(os.Args[2:])
	case "run", "replay", "fork", "bisect":
		fmt.Fprintf(os.Stderr, "hark %s: not implemented yet -- see docs/roadmap.md\n", os.Args[1])
		os.Exit(2)
	case "version", "--version", "-v":
		fmt.Println(Version)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "hark: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "hark:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `hark -- deterministic record and replay for AI agents, with a proof the replay is real

usage: hark <command> [arguments]

bundle commands
  verify   <bundle>            check a bundle end to end
  inspect  <bundle>            list the events in a bundle
  prove    <bundle> -seq N     emit an inclusion proof for one event
  synth    <bundle>            write a synthetic bundle, for testing
  keygen   -out <path>         create an Ed25519 signing key

runtime commands (not yet implemented)
  run, replay, fork, bisect

  version                      print the version
  help                         print this message
`)
}
