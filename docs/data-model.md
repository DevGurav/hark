# Data model

`hark` has no database. Its only persisted data is the `.hark` bundle, whose structure — header,
frames, footer, event kinds, and the hashing that binds them — is specified in
[protocol.md](protocol.md).

Key points that would otherwise live here:

- Bundles are append-only and immutable once sealed. There is no update path and no migration story
  for a written bundle; a format change means a new format version, and old bundles stay readable by
  the readers that understood them.
- Event kind numbers are frozen and never reused.
- Forks reference their parent by Merkle root rather than by filename, so the relationship survives
  files being renamed or moved. Forks form a DAG.

*Trigger: fill this in if `hark` ever gains an index, a bundle store, or any queryable state beyond
individual files.*
