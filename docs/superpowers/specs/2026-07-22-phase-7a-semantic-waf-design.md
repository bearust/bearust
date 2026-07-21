# Phase 7A: Semantic WAF Detection Design

## Goal

Extend the Phase 6 in-process signature WAF with deterministic, bounded semantic
signals that detect common attack intent after lightweight request
normalization. The feature must preserve the existing monitor-only default and
remain safe to run in the proxy request path.

## Scope

Phase 7A covers:

- bounded normalization of method, path, query, headers, and inspected body;
- semantic signals for SQL injection, cross-site scripting, path traversal,
  command injection, and protocol anomalies;
- deterministic risk scoring with conservative block thresholds;
- integration with existing signature rules, WAF modes, snapshots, audit
  events, and SSE invalidation behavior;
- unit, integration, and regression tests for detection, bypass resistance,
  limits, and mode behavior.

The following are explicitly out of scope: machine learning, external
detection services, network calls in the request path, bot management,
adaptive rate limiting, distributed synchronization, missed-event replay, and
persisted per-rule scoring configuration.

## Design

`InspectionContext` remains the evaluator input. A new bounded normalization
stage produces canonical field views using limited percent-decoding,
case-folding where appropriate, whitespace/separator canonicalization, and the
existing 8 KiB body inspection cap. Decoding must be bounded and must not turn
malformed input into an error that breaks proxying.

The semantic evaluator emits internal `SemanticSignal` values. Each signal
contains a category, severity/weight, source field, and a short redacted reason.
The evaluator combines semantic signals with the existing compiled signature
rules and returns the existing `WafDecision` plus bounded score/severity
metadata. Existing API and TOML rule formats remain backward compatible.

Evaluation is deterministic and bounded in both input size and work. If an
input exceeds an inspection limit or normalization cannot safely proceed, the
request is not blocked solely for that condition; a bounded diagnostic may be
recorded without retaining the original body or credentials.

The immutable `WafSnapshot` and atomic `WafStore` reload model remain unchanged.
Monitor-only maps detections to logging, while block mode applies a
conservative threshold. Existing explicit rule actions continue to take part in
the final decision, with blocking remaining dominant.

## Data flow

1. Proxy collects the bounded request context.
2. WAF normalizes eligible fields.
3. Signature rules and semantic detectors evaluate the normalized views.
4. The evaluator merges matches, score, categories, and redacted diagnostics.
5. Mode/action resolution produces allow, log, or block.
6. Existing audit and SSE paths receive only redacted metadata.

## Testing

Tests must cover:

- positive detection for each semantic category;
- normal benign requests that should not trigger a signal;
- single, mixed, and malformed encodings, including traversal variants;
- body and field-size limits;
- monitor-only versus block behavior and explicit rule precedence;
- immutable snapshot reload behavior;
- audit redaction and absence of full request/body persistence;
- proxy regression coverage for allowed and blocked requests.

## Success criteria

Phase 7A is complete when the semantic detector is integrated, all scoped tests
pass, Clippy and formatting checks pass, the Phase 7 documentation is updated,
and no out-of-scope capability is introduced into the request path.

