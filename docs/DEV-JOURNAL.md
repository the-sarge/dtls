<!--
SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
SPDX-License-Identifier: MIT
-->

# Development Journal

**Append-only. New entries go at the END of this file.**

Oldest entry first, most recent entry last.

---

## Endpoint identity verification merged - 2026-10-18 19:23 EDT

**Main:** `91e5e97bddd0`
**Actor:** Codex

### Summary

Merged [PR #1](https://github.com/the-sarge/dtls/pull/1) to require endpoint identity during normal server-certificate verification. Clients derive DNS or IP identities from destination addresses, reject missing identities, normalize derived absolute DNS names for SNI, and enforce the same identity policy on cached sessions. Explicit names, insecure verification, and PSK behavior remain supported. The fork’s existing lint and CodeQL caller jobs now declare their required permissions.

### Validation

Candidate `0aee7d64ddfe14984c957d4718591859899bc63c` passed the destination and cached-session regressions twice, the full race-enabled Go suite, changed-code lint, workflow syntax validation, commit metadata checks, and diff checks. Hosted platform tests passed their test steps; lint, CodeQL, API compatibility, tidy, REUSE, Anvil, and the other interoperability jobs passed.

Initial RAS review `20261018T225409-f8e9f3ea7cea65c3a8544dc2` found a trailing-dot SNI regression, which was fixed and verified on the exact candidate with blocking projection clear. Replacement review `20261018T230924-42c1ddb0af8f066e3905c340` completed with no required fixes or follow-ups. Two replacement adjudicators had structured-plan validation failures; the remaining adjudications and synthesis completed without a quorum failure.

### Decisions

The missing-token Codecov upload and external Pion-v4 certificate fixtures that omit ServerName were explicitly accepted as nonblocking for this merge, as recorded on [PR #1](https://github.com/the-sarge/dtls/pull/1). The fixture errors reflect the intended fail-closed behavior; no upstream repository changes were made.
