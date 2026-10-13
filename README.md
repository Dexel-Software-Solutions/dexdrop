# Dexdrop

### Enterprise-Oriented DevSecOps Security Scanner

**Find security risks earlier. Ship with confidence.**

A dependency-free, single-file Python security scanner for source
repositories, infrastructure configuration, container definitions, CI/CD
workflows, and dependency manifests.

```{=html}

**Built by [Demiyan
Dissanayake](https://github.com/dexel-software-solutions) · Dexel
Software Solutions**
:::

------------------------------------------------------------------------

## Overview

Dexdrop is a lightweight security-scanning tool designed to help
developers identify potentially risky patterns before they reach
production. It combines multiple analyzers in one Python file and can
generate human-readable reports as well as machine-readable output for
security workflows.

The scanner is designed for local development and CI/CD quality gates.
Findings include severity, a rule identifier, CWE mapping, remediation
guidance, a source location, and a stable fingerprint where applicable.

> **Important:** Dexdrop is a static-analysis aid, not a guarantee of
> security. It can produce false positives and false negatives. Review
> findings and validate results in the context of your application.

## Key capabilities

-   **Secret detection** --- identifies supported provider-token
    patterns, credential-bearing URLs, and likely hard-coded
    credentials; detected secret values are redacted in findings.
-   **Python SAST** --- AST-based checks for selected risky patterns,
    including dynamic execution, shell invocation, unsafe
    deserialization, insecure TLS/JWT settings, weak cryptography, and
    dynamic SQL construction.
-   **Dockerfile checks** --- flags selected container-hardening issues
    such as unpinned base images, root execution, remote scripts piped
    to a shell, and secrets in `ENV`/`ARG`.
-   **Infrastructure-as-Code checks** --- checks selected Terraform,
    CloudFormation-style, and Kubernetes configuration patterns.
-   **GitHub Actions checks** --- checks selected workflow patterns,
    including risky expression usage, broad write permissions, mutable
    action references, and `pull_request_target`.
-   **Dependency review** --- reads supported Python, npm, Ruby, Rust,
    Go, and PHP dependency manifests/lockfiles; optional OSV.dev lookup
    can check supported package data for known advisories.
-   **Actionable findings** --- rule IDs, severity, CWE references,
    remediation notes, and fingerprints.
-   **Baselines and suppressions** --- baseline existing findings and
    use inline `# dexdrop:ignore` directives where supported.
-   **CI-friendly exit codes** --- configure severity thresholds to fail
    a build when findings meet the selected level.
-   **Multiple report formats** --- console output plus JSON, SARIF
    2.1.0, and standalone HTML reports.
-   **Parallel scanning** --- scan files with a configurable worker
    count.
-   **Built-in regression tests** --- run the bundled test suite with
    `--self-test`.

## Analyzer coverage

  -----------------------------------------------------------------------
  Analyzer                            What it checks
  ----------------------------------- -----------------------------------
  Secrets                             Supported provider tokens,
                                      private-key markers, credential
                                      URLs, and likely hard-coded secrets

  Python SAST                         Selected unsafe execution,
                                      deserialization, TLS/JWT, SQL,
                                      crypto, temporary-file, XML,
                                      archive, and debug patterns

  Dockerfile                          Base-image pinning, non-root user,
                                      remote `ADD`, shell-piped
                                      downloads, embedded secrets, SSH
                                      exposure, and health checks

  IaC                                 Selected public access, broad
                                      CIDRs, privileged Kubernetes
                                      settings, encryption, database
                                      exposure, and wildcard IAM patterns

  GitHub Actions                      Selected expression-injection
                                      patterns, workflow permissions,
                                      mutable action references, and
                                      `pull_request_target` usage

  Dependencies                        Supported manifests and lockfiles,
                                      version pinning checks, and
                                      optional OSV.dev advisory queries
  -----------------------------------------------------------------------

Coverage is rule-based and intentionally finite. A clean scan does not
prove that a repository is free from vulnerabilities.

## Requirements

-   Python 3.11+ is recommended for the full dependency-manifest
    support, including `pyproject.toml` parsing through the
    standard-library `tomllib` module.
-   No third-party Python package is required for the scanner's core
    operation.
-   Network access is needed only when using `--online` for OSV.dev
    advisory lookups.

## Quick start

### 1. Get the script

Save the scanner as `dexdrop.py` in your repository, or clone/download
it from the project repository if you have published one.

### 2. Scan a repository

``` bash
python dexdrop.py .
```

### 3. Generate reports

``` bash
python dexdrop.py . --json reports/dexdrop.json --sarif reports/dexdrop.sarif --html reports/dexdrop.html
```

Make sure the output directory exists before running the command.

### 4. Run the built-in tests

``` bash
python dexdrop.py --self-test
```

### 5. Check the installed version and available rules

``` bash
python dexdrop.py --version
python dexdrop.py --list-rules
```

## Usage examples

### Scan a source directory

``` bash
python dexdrop.py ./src
```

### Scan and fail the quality gate on medium-or-higher findings

``` bash
python dexdrop.py . --fail-on medium
```

### Query OSV.dev for supported dependency advisories

``` bash
python dexdrop.py . --online
```

Use `--online` only when network access and external advisory queries
are acceptable for your environment.

### Create a baseline for an existing repository

``` bash
python dexdrop.py . --write-baseline .dexdrop-baseline.json
```

Then scan against that baseline:

``` bash
python dexdrop.py . --baseline .dexdrop-baseline.json
```

A baseline helps focus attention on findings not already recorded.
Review and refresh it deliberately; do not use it to hide newly
introduced risk.

### Exclude paths and disable individual rules

``` bash
python dexdrop.py . --exclude "vendor/*" --exclude "build/*"
python dexdrop.py . --disable-rule PY-WEAKHASH
```

Rule IDs can be discovered with `--list-rules`. Disabling a rule reduces
coverage and should be documented.

### Report without failing the build

``` bash
python dexdrop.py . --exit-zero --html reports/security.html
```

## Command-line options

  -----------------------------------------------------------------------
  Option                              Purpose
  ----------------------------------- -----------------------------------
  `PATH`                              File or directory to scan; defaults
                                      to the current directory

  `--exclude GLOB`                    Exclude matching paths; repeatable

  `--disable-rule RULE_ID`            Disable a rule; repeatable

  `--min-severity LEVEL`              Show findings at or above a
                                      severity

  `--fail-on LEVEL`                   Return a failing quality-gate exit
                                      code at or above a severity

  `--exit-zero`                       Report findings without failing the
                                      build

  `--online`                          Query OSV.dev for supported known
                                      dependency vulnerabilities

  `--json FILE`                       Write a JSON report

  `--sarif FILE`                      Write a SARIF 2.1.0 report

  `--html FILE`                       Write a self-contained HTML report

  `--baseline FILE`                   Suppress findings recorded in a
                                      baseline

  `--write-baseline FILE`             Write the current findings as a
                                      baseline and exit successfully

  `--max-file-size-kb KB`             Skip files larger than the
                                      configured size; default is 1024 KB

  `--workers N`                       Set the scan thread count

  `--no-color`                        Disable ANSI terminal colors

  `-q`, `--quiet`                     Suppress the console banner/report

  `-v`, `--verbose`                   Enable debug logging

  `--list-rules`                      Print the rule catalogue

  `--self-test`                       Run the built-in regression suite

  `--version`                         Print version information
  -----------------------------------------------------------------------

Severity levels are `info`, `low`, `medium`, `high`, and `critical`.

## Exit codes

  -----------------------------------------------------------------------
                                      Code Meaning
  ---------------------------------------- ------------------------------
                                       `0` Scan completed and the quality
                                           gate passed, or a command
                                           completed successfully

                                       `1` Findings met the configured
                                           `--fail-on` threshold

                                       `2` Usage or runtime error
  -----------------------------------------------------------------------

Run scans from the repository root when generating SARIF so reported
file paths align with the repository layout.

## Output formats

-   **Console** --- quick local feedback.
-   **JSON** --- structured output for scripts and downstream
    processing.
-   **SARIF 2.1.0** --- suitable for compatible code-scanning and
    security-reporting workflows.
-   **HTML** --- self-contained report for convenient local review.

Treat generated reports as potentially sensitive: they may contain file
paths, code snippets, and security findings. Store and share them
according to your organization's security policies.

## Configuration and suppressions

Dexdrop supports a project configuration file named `.dexdrop.json`,
rule disabling through `--disable-rule`, and inline suppressions in the
form:

``` python
# dexdrop:ignore
```

A rule-specific suppression can use:

``` python
# dexdrop:ignore[PY-SHELL]
```

Place suppression comments according to the scanner's supported parsing
behavior, and verify the effect with a test scan. Suppressions should be
narrow, justified, and reviewed---not used as a substitute for fixing a
vulnerability.

## Example workflow

A practical local workflow:

1.  Run `python dexdrop.py . --self-test` to check the bundled
    regression suite.
2.  Run a scan and review critical/high findings first.
3.  Fix confirmed issues and document accepted false positives.
4.  Generate SARIF/HTML/JSON reports for the team's review process.
5.  Introduce a baseline for legacy findings, then use `--fail-on` to
    gate newly introduced issues.
6.  Re-run scans after relevant code or dependency changes.

## Security and responsible use

-   Scan only repositories and systems you own or are explicitly
    authorized to assess.
-   Do not commit real secrets to test the scanner. Use synthetic test
    values.
-   If a real credential is detected, treat it as exposed: revoke or
    rotate it and remove it from source control history where
    appropriate.
-   Static scanning cannot replace code review, dependency governance,
    dynamic testing, threat modeling, or a comprehensive security
    assessment.
-   The optional online dependency lookup sends supported package
    identifiers and versions to OSV.dev. Review your organization's
    data-sharing requirements before enabling it.

## Known limitations

-   Detection is limited to implemented rules and supported file
    formats.
-   Static pattern matching and lightweight analysis can miss complex
    data flows and context-dependent vulnerabilities.
-   Some findings require manual triage and may be false positives.
-   Unsupported or unparsable files may not be fully analyzed; review
    scan warnings and coverage information.
-   OSV results depend on supported package extraction and the
    availability/quality of upstream advisory data.
-   A successful scan is not a security certification.

## Project information

  -------------------------------------------------------------------------------------------------------------
  Field                               Details
  ----------------------------------- -------------------------------------------------------------------------
  Project                             Dexdrop

  Version                             1.3.0

  Author                              Demiyan Dissanayake

  Organization                        Dexel Software Solutions

  GitHub organization                 [dexel-software-solutions](https://github.com/dexel-software-solutions)

  License                             Proprietary --- all rights reserved
  -------------------------------------------------------------------------------------------------------------

### License

Dexdrop is marked as **Proprietary --- © Dexel Software Solutions. All
rights reserved.** Do not describe or redistribute it as open source
unless the project owner changes the license and publishes the
applicable license terms.

------------------------------------------------------------------------

::: {align="center"}
**Dexdrop · Security checks that fit your development workflow.**

`<sub>`{=html}Designed for visibility, actionable findings, and
repeatable scanning---not as a substitute for security
judgment.`</sub>`{=html}
:::
