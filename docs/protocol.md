# Zcash Name Service Protocol

This document defines the core protocol for the Zcash Name Service (ZNS).
It is the source of truth for name identity, ownership, record updates, and
resolution semantics.

Policy decisions such as pricing, reserved names, grace periods, and rate
limits are intentionally separated from protocol invariants. If a rule affects
who can own a name, what state a name may be in, or how a resolver interprets
records, it belongs here. If a rule is about marketplace design, governance,
or operator preference, it belongs in policy.

## 1. Scope

ZNS assigns human-readable names to controller identity and associated
records. The protocol must support:

- registering names
- renewing expiring names
- transferring control
- updating name records
- revoking names
- resolving active names

The protocol is designed for the Zcash ecosystem and assumes that sensitive
operations may be mediated by a TEE-backed mint/registry daemon.

## 2. Terminology

- `name`: a human-readable label in the ZNS namespace.
- `label`: the canonical text form of a single name component.
- `namespace`: the set of all names governed by this protocol.
- `controller`: the entity authorized to manage a name.
- `owner`: the economic holder of a name. In the simplest deployment, owner and
  controller are the same.
- `resolver`: the system that interprets a name into usable records.
- `record`: the data associated with a name, such as payment destinations,
  contact data, or service metadata.
- `active`: a name that is currently valid and resolvable.
- `expired`: a name whose registration term has ended.
- `revoked`: a name that has been forcibly or administratively removed from
  active use.

## 3. Core Principles

- A name has exactly one current controller.
- Only the current controller may authorize state changes for that name.
- A name is either active or not active; resolution must not ambiguously return
  stale ownership.
- The protocol must be deterministic for a given chain state and registry
  state.
- Protocol rules are stable; policy values may evolve through governance.
- The mint/registry daemon is not authoritative by itself. It is an execution
  component that follows protocol rules and produces state transitions that can
  be validated independently.

## 4. Name Format

The canonical name format is lowercase ASCII with a restricted character set.
The initial allowed set should be:

- lowercase letters `a-z`
- digits `0-9`
- hyphen `-`

Additional constraints:

- names are case-insensitive and canonicalized to lowercase
- leading and trailing hyphens are disallowed
- consecutive hyphens may be restricted by policy if desired
- maximum and minimum length are policy parameters, not protocol constants

Canonicalization rules must be explicit and deterministic. Two inputs that
canonicalize to the same label must be treated as the same name.

## 5. Identity Model

Each name has a single canonical identity within the namespace.

The protocol must define:

- the canonical name string
- the current controller identity
- the current registration status
- the record set associated with the name
- the expiration timestamp or block height, if names expire

The controller identity may be represented by a transparent address, a viewing
key, a shielded spending key, or another protocol-defined authorization
primitive. The representation is a protocol choice and should remain stable
once chosen.

## 6. Name Lifecycle

A name moves through a finite state machine.

### States

- `available`
- `pending-registration`
- `active`
- `pending-update`
- `pending-transfer`
- `pending-revocation`
- `expired`
- `revoked`

### Transitions

- `available` -> `pending-registration` when a valid registration request is
  accepted
- `pending-registration` -> `active` when the registration becomes effective
- `active` -> `pending-update` when an authorized update is accepted
- `active` -> `pending-transfer` when an authorized transfer is accepted
- `active` -> `pending-revocation` when a revocation path is triggered
- `active` -> `expired` when the registration term ends
- `expired` -> `available` if the protocol allows re-registration after grace
  handling
- any non-terminal state -> `revoked` when the name is forcibly removed

The exact meaning of pending states depends on the settlement model. If the
implementation is immediate, pending states may be transient and only visible
internally. If the implementation is asynchronous, pending states must be
explicitly represented and replayable from chain data.

## 7. Operations

### 7.1 Register

Registers a new name.

Inputs:

- canonical name
- controller identity
- initial record set
- requested term or renewal period
- proof of authorization, if registration is gated

Requirements:

- the name must be available
- the requester must satisfy any eligibility rules
- the registration must obey all format and length constraints
- the registration must not violate reserved-name rules

Effects:

- create the name entry
- set the controller
- set the record set
- set the expiration, if names expire
- emit an auditable registration event

### 7.2 Renew

Extends the validity period of an active name.

Requirements:

- the name must be active or in a protocol-defined renewal window
- the caller must be authorized by the current controller model

Effects:

- extend the expiration or lease term
- preserve controller identity and existing records unless explicitly changed

### 7.3 Transfer

Changes controller ownership of a name.

Requirements:

- the current controller must authorize the transfer
- the destination controller must be valid
- policy may require a delay, challenge, or acceptance step

Effects:

- update controller identity
- preserve the name identity and registered record history unless policy says
  otherwise

### 7.4 Update

Changes the record set associated with a name.

Requirements:

- the current controller must authorize the update
- updated records must pass validation

Effects:

- replace or merge records according to the record model
- emit a versioned record update event

### 7.5 Revoke

Removes a name from active use.

Requirements:

- revocation must be explicitly authorized by the protocol
- revocation may be self-initiated, court-order driven, governance-driven, or
  fraud-driven depending on policy

Effects:

- mark the name revoked
- make it non-resolvable as an active name
- preserve enough history for auditability

### 7.6 Resolve

Looks up the current active data for a name.

Resolution must return only state that is valid at the queried chain height or
registry snapshot.

Resolution output should include:

- canonical name
- controller identity
- active status
- current record set
- expiration or validity metadata
- protocol version or schema version, if needed

Resolution must not expose secrets or require privileged access.

## 8. Record Model

The record model should be versioned and extensible.

Minimum recommended record classes:

- payment destination
- service endpoint
- contact or proof-of-control metadata
- optional text metadata

Rules:

- unknown record types must be ignored or preserved according to versioning
  rules
- record schemas must be machine-parseable and canonicalizable
- a resolver should be able to ignore fields it does not understand without
  breaking identity or ownership semantics

## 9. Authorization Model

Every mutable operation must have a clear authorization rule.

The protocol must specify:

- what key or identity type controls a name
- whether authorization is direct signature-based or mediated by a contract or
  mint transaction
- whether updates require one step or multiple steps
- whether recovery or social restoration is supported

If the system uses shielded credentials, the authorization proof must still be
deterministic and auditable at the protocol boundary.

## 10. State and Replay

The registry must be replayable from canonical history.

Requirements:

- the protocol must define the source of truth for state transitions
- all externally visible changes must be derivable from an ordered event log or
  chain state
- local caches are allowed, but they are not authoritative
- reorg handling must restore the previous valid state

If the mint/registry daemon is the executor, it must be able to reconstruct the
current registry state from the source of truth after a restart.

## 11. On-Chain vs Off-Chain Boundaries

The protocol must clearly separate:

- what is committed to chain
- what is derived off-chain
- what is merely cached locally

The recommended default is:

- on-chain: authoritative ownership and state transitions
- off-chain: indexes, caches, UX helpers, and display metadata

Secrets, recovery data, and operator internals must never be required for
public resolution.

## 12. Failure Cases

The protocol must define behavior for:

- attempted registration of an unavailable name
- invalid name syntax
- unauthorized update or transfer
- renewal after expiration
- lookup of unknown or revoked names
- chain reorganization
- duplicated or replayed requests
- conflicting pending operations

Failure responses should be explicit and stable so clients can reason about
them.

## 13. Security Requirements

- controllers must not be able to silently lose ownership
- name data must not be mutable by unauthorized parties
- replayed operations must not be accepted twice
- expiration rules must not create unsafe ambiguity
- the resolver must not reveal secret material
- the mint/registry daemon must not become a hidden trust oracle beyond the
  protocol rules

## 14. Policy Hooks

The following are policy, not protocol:

- registration fees
- renewal fees
- grace period duration
- reserved name list
- namespace segmentation
- rate limits
- eligibility requirements
- dispute resolution
- recovery procedures
- administrative backdoors, if any

Policy values should be documented separately, versioned independently, and
referenced by protocol version.

## 15. Versioning and Upgrades

The protocol must be versioned.

Rules:

- breaking changes require a new protocol version
- resolvers and clients must be able to detect incompatible versions
- upgrades must preserve the ability to interpret historical state
- deprecation windows should be explicit

## 16. Governance

Governance controls changes to policy and, where necessary, protocol evolution.

The governance model should answer:

- who may propose changes
- who may approve changes
- how changes are activated
- how emergency fixes are handled
- how disputes are recorded

Governance should not be able to rewrite history without an explicit and
auditable process.

## 17. Minimal Initial Recommendation

For the first implementation, the simplest viable protocol is:

- lowercase ASCII names only
- one controller per name
- expiring registrations with renewals
- direct controller-authorized updates and transfers
- simple versioned record blobs
- explicit revoke and expire semantics
- deterministic resolution from chain-backed registry state

This is intentionally small. Additional features such as subnames, delegated
controllers, multi-sig control, or advanced recovery can be added later if the
protocol versioning model supports them.

