# pattern-bench

[![Build status](https://ci.appveyor.com/api/projects/status/ns9iau87x4dbugif?svg=true)](https://ci.appveyor.com/project/0x1F9F1/pattern-bench)

A randomized benchmark for pattern scanners. Also good at finding bugs.

## Build

```powershell
cmake -S . -B build
cmake --build build --config Release
```

## Benchmark Modes

Use `--loglevel 1` for progress reporting.

### 1) Single Run (default mode)

Random synthetic data (default behavior):

```powershell
out\Release\bin\pattern-bench.exe --suite single --data_mode random --tests 64 --full true --loglevel 1
```

Single realistic corpus in single mode:

```powershell
out\Release\bin\pattern-bench.exe --suite single --data_mode synthetic_realistic --corpus mixed --tests 64 --full true --loglevel 1
```

### 2) Realistic Suite

Runs synthetic realistic corpora and prints per-corpus results + aggregate leaderboard.

All corpora:

```powershell
out\Release\bin\pattern-bench.exe --suite realistic --corpus all --tests 8 --full true --loglevel 1
```

One corpus only:

```powershell
out\Release\bin\pattern-bench.exe --suite realistic --corpus code --tests 8 --full true --loglevel 1
```

Available corpora:
- `mixed`
- `code`
- `structured`
- `text`
- `padding`
- `entropy`

### 3) Pathological Suite

Runs all pathological/degen stress cases and prints aggregate leaderboard:

```powershell
out\Release\bin\pattern-bench.exe --suite pathological --tests 8 --full true --loglevel 1
```

### 4) Combined Suite

Runs everything in one pass:
- random baseline
- realistic suite (all corpora)
- pathological suite (all cases)

```powershell
out\Release\bin\pattern-bench.exe --suite combined --tests 8 --full true --loglevel 1
```

## Useful Options

Filter to one scanner:

```powershell
out\Release\bin\pattern-bench.exe --suite combined --filter "x64dbg" --tests 8 --full true --loglevel 1
```

Lock seed for reproducibility:

```powershell
out\Release\bin\pattern-bench.exe --suite realistic --corpus all --seed 0x88BEA0B2 --tests 8 --full true --loglevel 1
```

Run only one generated test index:

```powershell
out\Release\bin\pattern-bench.exe --suite single --test 0 --tests 1 --full true --loglevel 4
```

Change region size (bytes):

```powershell
out\Release\bin\pattern-bench.exe --suite realistic --corpus all --size 33554432 --tests 8 --full true --loglevel 1
```

## Smoke Tests

Smoke-only check:

```powershell
out\Release\bin\pattern-bench.exe --smoke_only true
```

Skip smoke checks:

```powershell
out\Release\bin\pattern-bench.exe --skip_smoke
```

## File Benchmark

Benchmark against a real binary file (`--file` supports `--suite single` only):

```powershell
out\Release\bin\pattern-bench.exe --suite single --file "C:\path\to\binary.exe" --tests 64 --full true --loglevel 1
```

## Failure Logs

Failure details are always logged to unique files under:

```text
failure_logs/
```

Each run creates a timestamped JSONL session file, plus per-failure binary dumps when mismatches happen.
