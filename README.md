# pattern-bench

[![Build status](https://ci.appveyor.com/api/projects/status/ns9iau87x4dbugif?svg=true)](https://ci.appveyor.com/project/0x1F9F1/pattern-bench)

A randomized benchmark for pattern scanners. Also good at finding bugs.

## Leaderboard:

Scanning file: witcher3.exe<br/>
Begin Scan: Seed: 0x7FE81C77, Size: 0x2AF5000, Tests: 256, Skip Fails: true, Scanners: 8

Name | Speed
--- | ---
mem::simd_scanner                |  1929148619 cycles =  0.167 cycles/byte
mem::boyer_moore_scanner         | 11840465471 cycles =  1.027 cycles/byte
DarthTon                         | 36983612762 cycles =  3.207 cycles/byte
Simple                           | 39810411009 cycles =  3.452 cycles/byte
CFX                              | 45554670556 cycles =  3.951 cycles/byte
Forza (Boyer-Moore Variant)      | failed
mrexodia (horspool)              | failed
DarthTon v2                      | failed
