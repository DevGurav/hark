# Observability

`hark` emits no metrics, logs or traces of its own. It is a short-lived process whose entire output
is the bundle, and the bundle is a more complete record than any telemetry would be.

There is a genuine tension worth naming: the supervisor is the thing recording everything else, so
instrumenting it raises the question of who records the recorder. The current answer is that its
behaviour is fully described by the artifact it produces — every boundary crossing it mediated is an
event, including the ones it denied.

*Trigger: fill this in when a long-running process appears (a hosted trace viewer, a daemon mode, or
a mediator shared across runs). At that point operator-facing telemetry becomes necessary and the
recorder-recording-itself question needs a real answer rather than a deferral.*
