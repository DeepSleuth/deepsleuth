# Changelog

All notable changes to deepsleuth are documented here. The format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows [semver](https://semver.org/).

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

