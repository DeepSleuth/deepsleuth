# Changelog

All notable changes to deepsleuth are documented here. The format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows [semver](https://semver.org/).

## [0.5.1] — 2026-05-08

fixes.

- fix pin migration when a tool's schema changes legitimately

## [0.5.0] — 2026-04-24

inline gateway + calibration.

- transparent stdio MCP proxy with a pre-call gate
- shared additive calibration layer (severity/confidence split)
- server-identity pinning across sessions
- response-injection, response-leak and auth-gap detectors

## [0.4.1] — 2026-01-30

fixes.

- fix sandbox timeout handling for slow-starting servers
- graceful degradation when the docker CLI is absent

## [0.4.0] — 2026-01-09

sandbox scanner frontend.

- batch/sandbox scanner: launch targets in a hardened Docker sandbox
- deterministic call-plan driver with synthesized arguments + canaries
- target loader: directory / mcp.json / raw launch command

## [0.3.1] — 2025-10-17

fixes.

- fix exit codes honoring confidence floors
- fix tools/list parsing for servers without descriptions

## [0.3.0] — 2025-09-26

static analysis engine.

- taint tracking with one level of call inlining + sanitizer modeling
- privilege, env-dump, constant-assembly, static-response detectors
- first bundled fixtures + offline scoring harness

## [0.2.0] — 2025-06-20

first detectors + CLI.

- description/schema poisoning detector with obfuscation checks
- text-mechanism rule engine, reporter, phased detector runner
- python AST analysis: tool extraction + behavior facts

## [0.1.0] — 2025-04-10

first skeleton.

- core data models and deterministic text-normalization pipeline
- CLI entry point (`python -m deepsleuth`)

