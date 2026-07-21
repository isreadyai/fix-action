# Changelog

All notable changes to the **isready.ai AI-readiness fix PR** action are recorded
here. This file is **generated** from the
[`isreadyai/isreadyai`](https://github.com/isreadyai/isreadyai) monorepo release
notes on each release — do not edit by hand.

## Unreleased

## v1.0.6 — 2026-07-21

## v1.0.5 — 2026-07-10

## v1.0.4 — 2026-07-07

## v1.0.3 — 2026-07-07

## v1.0.2 — 2026-07-07

- Bundle the CI report + repo-badge upload (`dist/ci-upload.js`) into the fix action too, so the CI Reports dashboard and repo badge populate for fix-only users.
- Demote the request-budget pruning notice to a debug-level log — quieter normal runs.
- Refresh the bundled scanner from the monorepo.

## v1.0.1 — 2026-07-05

## v1.0.0 — 2026-07-02

- Initial extraction of the AI-readiness fix PR action into its own
  Marketplace-listable repository, shipping a committed, node-target `dist/`
  bundle (scan + in-runner fix agent, zero runtime deps) — no `bun install` at
  runtime.
- See the monorepo
  [CHANGELOG](https://github.com/isreadyai/isreadyai/blob/main/CHANGELOG.md) for
  the engine, CLI and fix-agent history.
