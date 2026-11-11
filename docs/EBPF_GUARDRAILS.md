# eBPF guardrails

## Relevant practice

- Functional selftests run in a booted kernel and are a hard CI gate.
- Performance claims are normally review evidence rather than a universal CI
  threshold.
- Good performance patches report the workload, hardware, kernel config,
  compiler, repetitions, variance, and unchanged or worse cases.
- BPF's benchmark framework controls warmup, duration, CPU affinity, and
  producer/consumer counts, and emits explicit before/after comparisons.
- CI can compare verifier statistics against a baseline, but missing baselines
  do not automatically fail every run.

## Lua-LSM consequence

The external suite owns the full gate:

1. Boot a controlled kernel and run functional assertions before performance.
2. Capture kernel logs and fail on WARN, OOPS, lockdep, KASAN, or KFENCE splats.
3. Run stability stress separately from short functional cells.
4. Record environment, repetitions, mean, and standard deviation for benchmarks.
5. Compare against a named baseline from the same host and image.
6. Require a noise budget before a performance threshold can fail CI.

A performance optimization is not accepted merely because it is plausible. The
change must preserve functional behavior and show a measurable benefit outside
the workload's noise range.

## Sources

- <https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/README.rst>
- <https://www.kernel.org/doc/html/latest/bpf/bpf_devel_QA.html>
- <https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/bench.c>
- <https://docs.kernel.org/process/5.Posting.html>
