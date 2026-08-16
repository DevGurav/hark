package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/DevGurav/hark/internal/bundle"
	"github.com/DevGurav/hark/internal/logfmt"
)

func cmdInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	limit := fs.Int("n", 0, "show at most this many events (0 means all)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: hark inspect [-n N] <bundle>")
	}

	r, err := bundle.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer r.Close()

	h := r.Header()
	fmt.Printf("run       %s\n", h.RunID)
	fmt.Printf("created   %s\n", time.Unix(0, h.CreatedAt).Format(time.RFC3339Nano))
	fmt.Printf("recorder  %s\n", h.Recorder)
	if len(h.ParentRoot) > 0 {
		fmt.Printf("forked    from root %x at seq %d\n", h.ParentRoot, h.ForkPoint)
	}
	fmt.Println()
	fmt.Printf("%-6s %-18s %-12s %s\n", "SEQ", "KIND", "AT", "SUMMARY")

	var shown int
	for {
		f, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			fmt.Println("\n-- log truncated here: the run was killed mid-write")
			break
		}
		if err != nil {
			return err
		}

		fmt.Printf("%-6d %-18s %-12s %s\n",
			f.Seq, f.Kind, formatMono(f.MonoNanos), summarise(f))

		shown++
		if *limit > 0 && shown >= *limit {
			fmt.Println("...")
			break
		}
	}

	if foot := r.Footer(); foot != nil {
		fmt.Printf("\nsealed at %d events, root %x\n", foot.LeafCount, foot.Root)
	}
	return nil
}

func formatMono(ns uint64) string {
	return time.Duration(ns).Round(time.Millisecond).String()
}

// summarise renders a one-line description of an event.
//
// Decoding is best-effort by design. A bundle written by a newer recorder may
// carry kinds this build does not know, and inspect should still list them
// rather than refusing the whole file -- verification never needed the payload
// decoded, only hashed.
func summarise(f *logfmt.Frame) string {
	switch f.Kind {
	case logfmt.KindRunStart:
		var v logfmt.RunStart
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			return fmt.Sprintf("%s in %s", v.Recorder, v.WorkingDir)
		}
	case logfmt.KindPolicyLoaded:
		var v logfmt.PolicyLoaded
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			return fmt.Sprintf("%s, %d hosts allowed", v.Source, len(v.AllowHosts))
		}
	case logfmt.KindEnvSnapshot:
		var v logfmt.EnvSnapshot
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			return fmt.Sprintf("%d variables", len(v.Vars))
		}
	case logfmt.KindFsManifest:
		var v logfmt.FsManifest
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			return fmt.Sprintf("%s, %d files hashed", v.Root, len(v.Entries))
		}
	case logfmt.KindLLMRequest:
		var v logfmt.LLMRequest
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			return fmt.Sprintf("%s %s%s (%d bytes, occurrence %d)", v.Method, v.Host, v.Path, len(v.Body), v.Occurrence)
		}
	case logfmt.KindLLMResponseChunk:
		var v logfmt.LLMResponseChunk
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			return fmt.Sprintf("chunk %d, %d bytes", v.Seq, len(v.Data))
		}
	case logfmt.KindLLMResponseEnd:
		var v logfmt.LLMResponseEnd
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			if v.Error != "" {
				return fmt.Sprintf("status %d after %d chunks, error: %s", v.Status, v.ChunkCount, v.Error)
			}
			return fmt.Sprintf("status %d after %d chunks", v.Status, v.ChunkCount)
		}
	case logfmt.KindToolCallRequest:
		var v logfmt.ToolCallRequest
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			return fmt.Sprintf("%s/%s", v.Server, v.Tool)
		}
	case logfmt.KindToolCallResult:
		var v logfmt.ToolCallResult
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			if v.IsError {
				return fmt.Sprintf("%s/%s -> error", v.Server, v.Tool)
			}
			return fmt.Sprintf("%s/%s -> %d bytes", v.Server, v.Tool, len(v.Result))
		}
	case logfmt.KindDNSQuery:
		var v logfmt.DNSQuery
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			if v.Name == "" {
				return v.Type
			}
			return fmt.Sprintf("%s %s", v.Type, v.Name)
		}
	case logfmt.KindDNSDecision:
		var v logfmt.DNSDecision
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			verdict := "policy: DENIED"
			if v.Allowed {
				verdict = "policy: allowed"
			}
			if v.Answer != "" {
				return fmt.Sprintf("%s -> %s (%s)", v.Name, v.Answer, verdict)
			}
			return fmt.Sprintf("%s (%s) %s", v.Name, verdict, v.Reason)
		}
	case logfmt.KindEgressAttempt:
		var v logfmt.EgressAttempt
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			return fmt.Sprintf("%s:%d (%s)", v.Host, v.Port, v.Protocol)
		}
	case logfmt.KindEgressDecision:
		var v logfmt.EgressDecision
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			verdict := "DENIED"
			if v.Allowed {
				verdict = "allowed"
			}
			return fmt.Sprintf("%s %s by %s: %s", verdict, v.Host, v.Rule, v.Reason)
		}
	case logfmt.KindSecretInjected:
		var v logfmt.SecretInjected
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			return fmt.Sprintf("%s -> %s", v.Placeholder, v.Host)
		}
	case logfmt.KindClockRead:
		var v logfmt.ClockRead
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			return v.Source
		}
	case logfmt.KindRandomRead:
		var v logfmt.RandomRead
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			return fmt.Sprintf("%s, %d bytes", v.Source, len(v.Data))
		}
	case logfmt.KindCheckpoint:
		var v logfmt.Checkpoint
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			return fmt.Sprintf("%s state %x", v.Label, v.StateHash)
		}
	case logfmt.KindRunEnd:
		var v logfmt.RunEnd
		if logfmt.Unmarshal(f.Payload, &v) == nil {
			return fmt.Sprintf("exit %d (%s)", v.ExitCode, v.Reason)
		}
	}
	return fmt.Sprintf("%d bytes", len(f.Payload))
}
