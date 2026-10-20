# Xtro-ZIP V1 metadata documentation

- [FORMAT.md](FORMAT.md) — implementer-oriented binary format, validation,
  interoperability, encryption, archive-graph semantics and future ACL/label
  extension requirements.
- `../../xtrmeta/M1-WIRE-REVIEW.md` — historical design and allocation
  review; the V1 implementation in the current source supersedes historical
  milestone status statements in older notes.
- `../../xtrmeta/xtrv1.h` — public C89 functions; `xtrv1.c` is the normative
  implementation of current field validation and serialization.

No Multics ACL/security-label type or native restoration API has been
standardized. Preserve unknown records when copy-safe, but never restore them
under an invented local interpretation.
