package report

import "html/template"

// The whole page: markup, style, and nothing else.
//
// html/template escapes every value by context, which matters more here than
// anywhere else in the project -- a recorded body is attacker-controlled by
// construction. A prompt-injected agent's traffic is exactly the content this
// page displays, so a report that interpolated it raw would be a way to attack
// the reviewer with the evidence.
var tmpl = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>hark trace {{.RunID}}</title>
<style>
:root {
  color-scheme: light dark;
  --bg: #fbfbfa; --fg: #1a1a1a; --dim: #6b6b6b; --line: #e0dedb;
  --card: #ffffff; --code: #f4f3f1;
  --deny: #b3261e; --deny-bg: #fdeceb;
  --secret: #8a5a00; --secret-bg: #fdf5e6;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #16171a; --fg: #e6e4e1; --dim: #9a9894; --line: #2c2e33;
    --card: #1d1f23; --code: #232529;
    --deny: #ff8a80; --deny-bg: #3a1d1b;
    --secret: #ffc766; --secret-bg: #33280f;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2rem 1.25rem 4rem; background: var(--bg); color: var(--fg);
  font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
main { max-width: 68rem; margin: 0 auto; }
h1 { font-size: 1.35rem; margin: 0 0 .25rem; letter-spacing: -0.01em; }
h1 .sub { color: var(--dim); font-weight: 400; font-size: .95rem; }
code, pre, .mono { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace; }

.card { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 1rem 1.15rem; margin: 1.25rem 0; }
dl.head { display: grid; grid-template-columns: max-content 1fr; gap: .35rem 1.25rem; margin: 0; }
dl.head dt { color: var(--dim); }
dl.head dd { margin: 0; overflow-wrap: anywhere; }
.badge { display: inline-block; padding: .1rem .5rem; border-radius: 999px; font-size: .8rem; border: 1px solid var(--line); }
.badge.sealed { color: #1f7a3d; border-color: #1f7a3d55; }
.badge.truncated, .badge.broken { color: var(--deny); border-color: var(--deny); background: var(--deny-bg); }

table { width: 100%; border-collapse: collapse; }
th { text-align: left; font-size: .78rem; letter-spacing: .06em; text-transform: uppercase; color: var(--dim); font-weight: 600; padding: 0 .6rem .4rem; }
td { border-top: 1px solid var(--line); padding: .4rem .6rem; vertical-align: top; }
td.seq, td.at { color: var(--dim); white-space: nowrap; width: 1%; }
td.kind { white-space: nowrap; width: 1%; }
tr.denial td { background: var(--deny-bg); }
tr.denial td.kind, tr.denial td.summary { color: var(--deny); font-weight: 600; }
tr.secret td.kind { color: var(--secret); }
tr.framing td.kind { color: var(--dim); }

details { margin: .3rem 0 0; }
summary { cursor: pointer; color: var(--dim); font-size: .85rem; }
summary::marker { color: var(--line); }
dl.detail { display: grid; grid-template-columns: max-content 1fr; gap: .2rem .9rem; margin: .5rem 0 0; font-size: .88rem; }
dl.detail dt { color: var(--dim); }
dl.detail dd { margin: 0; overflow-wrap: anywhere; }
pre.body { background: var(--code); border: 1px solid var(--line); border-radius: 6px; padding: .6rem .7rem; margin: .5rem 0 0;
  white-space: pre-wrap; overflow-wrap: anywhere; font-size: .85rem; max-height: 26rem; overflow: auto; }
.note { color: var(--dim); font-size: .85rem; }
.counts { columns: 3 12rem; font-size: .9rem; }
footer { color: var(--dim); font-size: .82rem; margin-top: 2rem; }
</style>
</head>
<body>
<main>

<h1>hark trace <span class="mono">{{.RunID}}</span></h1>
<div class="sub note">{{.Path}} &middot; recorded by {{.Recorder}} &middot; {{.Created}}</div>

<section class="card">
<dl class="head">
  <dt>verification</dt>
  <dd><span class="badge {{.Status}}">{{.Status}}</span>{{if .Problem}} <span class="note">{{.Problem}}</span>{{end}}</dd>
  <dt>events</dt><dd>{{.Events}}</dd>
  <dt>merkle root</dt><dd class="mono">{{.Root}}</dd>
  <dt>chain head</dt><dd class="mono">{{.Chain}}</dd>
  <dt>signature</dt><dd class="mono">{{.Signature}}</dd>
  <dt>transparency</dt><dd>{{.Anchor}}</dd>
{{with .Parent}}
  <dt>forked from</dt><dd class="mono">{{.Root}}</dd>
  <dt>branch point</dt><dd>event {{.Point}}</dd>
  <dt>patch</dt><dd class="mono">{{.Patch}}</dd>
{{end}}
</dl>
</section>

<section class="card">
<table>
<thead><tr><th>seq</th><th>at</th><th>kind</th><th>event</th></tr></thead>
<tbody>
{{range .Rows}}
<tr class="{{.Class}}">
  <td class="seq mono">{{.Seq}}</td>
  <td class="at">{{.At}}</td>
  <td class="kind">{{.Kind}}</td>
  <td class="summary">{{.Summary}}
  {{if or .Fields .Body}}
    <details>
      <summary>detail</summary>
      {{if .Fields}}<dl class="detail">{{range .Fields}}<dt>{{.Name}}</dt><dd class="mono">{{if .Value}}{{.Value}}{{else}}&mdash;{{end}}</dd>{{end}}</dl>{{end}}
      {{if .Body}}<div class="note">{{.BodyOf}}</div><pre class="body">{{.Body}}</pre>
        {{if .More}}<div class="note">{{.More}} further bytes not shown</div>{{end}}
      {{end}}
    </details>
  {{end}}
  </td>
</tr>
{{end}}
</tbody>
</table>
{{if .Killed}}<p class="note">The log ends here: the run was killed mid-write, and everything above it still verifies.</p>{{end}}
</section>

<section class="card">
<div class="note">events by kind</div>
<div class="counts">{{range .Counts}}<div>{{.Kind}} &middot; {{.N}}</div>{{end}}</div>
</section>

<footer>
Rendered by hark at {{.Generated}} from {{.Path}}. This page shows what the bundle contains and what
<code>hark verify</code> found when it was rendered; it does not verify anything itself. Re-run
<code>hark verify</code> against the bundle to check that for yourself.
</footer>

</main>
</body>
</html>
`))
