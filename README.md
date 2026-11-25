# Lafke benchmarks

Reproducible benchmarks for the [Lafke](https://github.com/lafke/lafke) CLI and its analysis
engine: **speed and memory**, and **detection accuracy** on public suites whose vulnerable and safe
cases are labeled. Every measurement runs against source pinned to an exact commit, so anyone can
repeat it and compare the numbers.

A fast run says nothing about what was found, so read speed and accuracy together.

## Reproduce

You need Go (the version in [`go.mod`](go.mod)), `git`, and `lafke` with an engine installed
(`curl -fsSL https://lafke.sh/install | sh`). Run the commands from the repository root.

```sh
go run ./cmd/bench                           # every corpus, 1 warm-up and 5 timed runs where timed
go run ./cmd/bench -only juliet-java         # one corpus (repeatable)
go run ./cmd/bench -runs 0                   # accuracy only, no timing: the fast mode
go run ./cmd/bench -jobs 8                   # parallel git operations and lafke runs
go run ./cmd/bench -lafke ./lafke            # a specific executable
go run ./cmd/bench -list                     # the corpus names
```

The program fetches each corpus into `.cache/` at the revision in [`corpora.json`](corpora.json),
fails if the checkout does not match it, and writes a JSON result to `results/`. A corpus that is
already at its revision is not fetched again.

## Corpora

| Corpus | Source | Cases | Scored how |
| --- | --- | --- | --- |
| `owasp-benchmark-java`, `owasp-benchmark-python` | [OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava), [BenchmarkPython](https://github.com/OWASP-Benchmark/BenchmarkPython) | 2,740 and 1,230 | the rule of the case's category reports in its file |
| `juliet-java` | [NIST Juliet Test Suite](https://samate.nist.gov/SARD/test-suites/111), Java, from a [copy](https://github.com/find-sec-bugs/juliet-test-suite) | the bad and good parts of the test cases whose CWE is in scope | a finding with the CWE inside a `bad*` or `good*` method |
| `benchproctor-<language>` | [BenchProctor](https://github.com/TheAuditorTool/BenchProctor), standalone cases of Go, Java, JavaScript, PHP, Python, Ruby and TypeScript | 40 cases per category and framework | a finding with the case's CWE in its file |
| `kics-iac` | [Checkmarx KICS](https://github.com/Checkmarx/kics), the test files of its queries for Terraform, Dockerfile, Compose, Kubernetes and GitHub Actions | one case per positive or negative file of the queries mapped to a lafke rule | a finding of a mapped rule in the case's file |
| `snyk-vulnbench` | [Snyk VulnBench](https://github.com/snyk-labs/snyk-vulnbench), fixtures with an attacker-reachable answer key | 108 vulnerabilities | a finding of the type near the source-to-sink flow |

The corpora are downloaded when you run the program. Their source is not copied here and keeps its
own license: OWASP Benchmark is GPL, BenchProctor, KICS and VulnBench are Apache-2.0 and Juliet is a NIST work.

## Accuracy

A case is vulnerable or safe, and belongs to a category.

| Term | Meaning |
| --- | --- |
| TP (true positive) | a vulnerable case that lafke reports |
| FP (false positive) | a safe case that lafke reports |
| FN (false negative) | a vulnerable case that lafke does not report |
| TN (true negative) | a safe case that lafke does not report |
| Recall | TP / (TP + FN): the share of vulnerable cases found |
| Precision | TP / (TP + FP): the share of reports that are vulnerable |
| F1 | 2 x recall x precision / (recall + precision) |
| J | Youden's J: recall minus the false-positive rate FP / (FP + TN). 0 is no better than flagging everything or nothing |

Every label is in the denominator, including a case lafke could not analyze. The JSON holds the
number of `sast:analysis-incomplete` findings, and of units where lafke did not finish in time
(`-unit-timeout`); such a unit has no findings, so its vulnerable cases are false negatives.

### How each corpus is scored

- **OWASP Benchmark**: each category maps to one lafke rule in `corpora.json`. A case is a hit when
  that rule reports a finding in the case's file.
- **BenchProctor**: each framework folder is analyzed as a unit (with its dependency manifest next
  to `testcode/`). A case is a hit when a finding in its file has the case's CWE, or one of the same
  group. Categories lafke does not attempt (`null_deref`, `intoverflow`) are left out and counted as
  excluded. The official scorer requires the exact CWE. lafke reports one generic CWE per rule
  (CWE-327 for every weak cipher or hash, CWE-338 for weak randomness), so exact matching would
  count a correct finding as a miss. **The numbers are therefore not comparable with scores from the
  official scorer.**
- **Juliet**: a test case has a bad part (methods named `bad*`) and a good part (`good*`). A case can
  be spread over several files (flow variant 54a to 54e, or the base, bad and good classes of 81);
  its files are scored as one. A finding with the CWE of the directory inside a bad method makes the
  vulnerable case a hit; inside a good method it is a false positive for the safe case. Only CWEs in a group are scored; the other
  directories are counted as excluded. Each CWE directory (or `sNN` subdirectory) is a unit, so
  they run in parallel.
- **KICS**: this is lafke's own reading of the query tests, not a KICS score. KICS has far more
  queries than lafke has `sast:iac/*` rules, so only the queries that `queries` in `corpora.json`
  maps to a lafke rule are scored; every other query is left out, and the scores say nothing
  about it. A positive file (listed in the query's `positive_expected_result.json`) is a hit when
  a mapped rule reports a finding in it that also satisfies any `query_filters` entry. The
  same match in a negative file is a false positive. Filters can match the finding's detail,
  resource subject or reported ingress ports. Known and unknown port checks use the port
  catalog from the pinned KICS revision. The reported line is not compared. Each case is copied into a directory of its own under
  `.cache/` and named as lafke finds it (`Dockerfile`, `docker-compose.yml`,
  `.github/workflows/`), because KICS names them `positive1.dockerfile` and so on. A case that is
  a directory, or in another format (JSON, Bicep), is counted as excluded. The mapping is a
  judgment of which queries mean the same weakness as a rule, so another mapping gives other numbers.
- **VulnBench**: this is lafke's own reading of the answer key, not the VulnBench scorer. A
  vulnerability is found when a finding whose rule name equals its type (or an alias) lies within
  3 lines of a location of its source-to-sink flow. The key names no safe cases, so only recall is
  defined; precision, F1 and J are shown as a dash.

**CWE groups.** `cwe_groups` in `corpora.json` lists the CWEs that mean the same weakness for these
comparisons, such as 79, 80 and 87 for cross-site scripting. A corpus that uses them only scores the
CWEs that are in a group.

### Read the scores with care

- Most suites are synthetic, and their ratio of vulnerable to safe cases differs from a real
  repository. The scores do not predict accuracy on an arbitrary application.
- The KICS cases are minimal files for one query each, and lafke may report a different, correct
  finding in a negative file. Only the mapped rule counts there.
- Lafke's analysis is developed against suites like these, so this is not a held-out evaluation.
- A score only means something next to another tool that ran on the same revisions and the same
  cases, scored the same way.

## Speed

Speed is measured, and accuracy is scored, with different parts of the program:

- Corpora are fetched at the same time, and the units of all corpora (`-jobs`, half the CPUs by
  default) are analyzed on one pool. The accuracy of the whole set takes about as long as the
  slowest unit.
- Wall time and peak memory are only measured for a corpus that is one tree, in fresh processes one
  after the other, after one discarded warm-up run. Parallel runs would disturb each other.
- **Wall time** is the elapsed time of the whole command, including starting the engine. **Peak
  memory** is the maximum resident set size of `lafke` and the processes it started. It is not
  measured on Windows and reported as 0.
- The result records min, median, mean and standard deviation, every raw sample, and the
  environment: OS, architecture, CPU count, Go, `lafke` and engine versions.

## Results in GitHub Actions

The [Benchmark workflow](.github/workflows/bench.yml) runs every Monday, on pushes that change it,
and on demand (**Actions > Benchmark > Run workflow**, where you can set the number of runs, the
`lafke` version and which corpora to run). One job per corpus runs on its own runner, so the timed
corpora do not share a machine and the whole set takes as long as the slowest corpus. The fetched
corpora are cached. A final job merges the results and writes:

- a table of speed and memory, and a table of TP, FP, FN, TN, recall, precision, F1 and J with a
  breakdown by category, in the **job summary**,
- every JSON result, as the `benchmark-results` **artifact**.

Shared runners are noisy, so compare runs of the same workflow with each other, not with your own
machine. Accuracy does not depend on the machine, only on the `lafke` and engine versions.

## Adding a corpus

Add an entry to [`corpora.json`](corpora.json) with its `kind`, the repository URL, the full
40-character commit hash (never a branch or tag) and the `lafke` command, then run it once. A new
kind of labels needs a suite in `cmd/bench` that fetches the corpus, splits it into units and
scores their findings.

## License

[Apache-2.0](LICENSE), for the code in this repository.
