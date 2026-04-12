# SKWS - Swiss Knife for Web Security

![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)

A context-aware, behavior-based web security scanner. SKWS combines 31 built-in detection modules with external tool integration and maps every finding to OWASP frameworks (WSTG, Top 10 2021, API Top 10 2023).

## Architecture

```mermaid
flowchart TD
    CLI["CLI (cobra)"]
    Scanner["Scanner Engine"]
    HTTP["HTTP Client"]
    Detection["Detection Modules (31 detectors)"]
    Tools["External Tools\n(SQLMap, Nuclei, ffuf)"]
    Templates["Template Engine"]
    Context["Context Analyzer"]
    Behavior["Behavior Detector"]
    OOB["OOB Callback Server\n(interactsh)"]
    Payloads["Payload Library"]
    OWASP["OWASP Mapper"]
    Reporter["Reporter"]

    CLI --> Scanner
    Scanner --> HTTP
    Scanner --> Detection
    Scanner --> Tools
    Scanner --> Templates
    Detection --> Context
    Detection --> Behavior
    Detection --> OOB
    Detection --> Payloads
    Detection --> HTTP
    Tools --> HTTP
    Templates --> HTTP
    Scanner --> OWASP
    OWASP --> Reporter

    Reporter --> JSON["JSON"]
    Reporter --> Text["Text"]
```

## Features

- **31 detection modules** covering injection, XSS, SSRF, misconfigurations, auth flaws, and more
- **Context-aware detection** - analyzes reflection context, parameter types, and response behavior
- **Behavioral analysis** - detects anomalies through timing differentials and content analysis
- **Out-of-band testing** - blind vulnerability detection via interactsh callbacks
- **OWASP mapping** - every finding mapped to WSTG, Top 10 2021, and API Top 10 2023
- **External tool integration** - SQLMap, Nuclei, ffuf with normalized output
- **Template engine** - extensible Nuclei-style templates for custom checks
- **Technology fingerprinting** - wappalyzergo-based stack detection
- **Multiple output formats** - JSON and text
- **Proxy support** - route traffic through Burp, ZAP, or any HTTP proxy

## Scan Pipeline

```mermaid
sequenceDiagram
    participant User
    participant CLI
    participant Scanner
    participant HTTP as HTTP Client
    participant Target
    participant Detection
    participant OWASP as OWASP Mapper
    participant Reporter

    User->>CLI: skws scan [target]
    CLI->>Scanner: Config + Target
    Scanner->>HTTP: Probe target
    HTTP->>Target: Initial request
    Target-->>HTTP: Response
    HTTP-->>Scanner: Baseline response

    Scanner->>Detection: Run 31 detectors concurrently

    loop Each Detector
        Detection->>HTTP: Inject payloads
        HTTP->>Target: Crafted request
        Target-->>HTTP: Response
        HTTP-->>Detection: Analyze response
        Detection-->>Scanner: Findings
    end

    Scanner->>OWASP: Map findings to frameworks
    OWASP-->>Scanner: WSTG + Top10 + API Top10
    Scanner->>Reporter: Generate report
    Reporter-->>User: JSON / Text
```

## Installation

**Build from source:**

```bash
git clone https://github.com/swiss-knife-for-web-security/skws.git
cd skws
make build
```

**Install to GOPATH:**

```bash
make install
```

**Cross-platform builds:**

```bash
make build-all  # Linux, macOS (amd64+arm64), Windows
```

## Usage

```bash
# Basic scan
skws scan https://example.com/page?id=1

# POST request with data
skws scan -X POST -d "user=admin&pass=test" https://example.com/login

# Custom headers and cookies
skws scan -H "Authorization: Bearer token" --cookie "session=abc" https://example.com

# Aggressive scan (level 1-5, risk 1-3)
skws scan --level 5 --risk 3 https://example.com/page?id=1

# Through a proxy
skws scan --proxy http://127.0.0.1:8080 https://example.com

# JSON output
skws scan --json https://example.com > results.json

# Disable out-of-band testing
skws scan --no-oob https://example.com

# Verbose mode
skws scan -v https://example.com

# List and check external tools
skws tools list
skws tools check
```

### Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--verbose` | `-v` | Enable verbose output | `false` |
| `--output` | `-o` | Output file path | stdout |
| `--proxy` | | Proxy URL | |
| `--timeout` | `-t` | Scan timeout | `30m` |
| `--concurrency` | `-c` | Concurrent tools | `3` |
| `--header` | `-H` | Custom header (repeatable) | |
| `--cookie` | | Cookie string | |
| `--data` | `-d` | POST data | |
| `--method` | `-X` | HTTP method | `GET` |
| `--level` | | Scan level (1-5) | `1` |
| `--risk` | | Risk level (1-3) | `1` |
| `--json` | | JSON output | `false` |
| `--no-oob` | | Disable OOB testing | `false` |

## Detection Modules

```mermaid
flowchart LR
    subgraph Injection
        SQLi[SQL Injection]
        XSS[Cross-Site Scripting]
        CMDi[Command Injection]
        SSTI[Server-Side Template Injection]
        CSTI[Client-Side Template Injection]
        NoSQL[NoSQL Injection]
        LDAP[LDAP Injection]
        XPath[XPath Injection]
        XXE[XML External Entity]
        JNDI[JNDI Injection]
    end

    subgraph File["File Inclusion"]
        LFI[Local File Inclusion]
        RFI[Remote File Inclusion]
    end

    subgraph ServerSide["Server-Side"]
        SSRF[SSRF]
        Smuggling[HTTP Smuggling]
    end

    subgraph Auth["Auth & Access"]
        AuthMod[Authentication]
        JWT[JWT Vulnerabilities]
        IDOR[IDOR / BOLA]
        GraphQL[GraphQL]
        CORS[CORS Misconfig]
    end

    subgraph Config["Config & Exposure"]
        SecHeaders[Security Headers]
        TLS[TLS Issues]
        Exposure[Data Exposure]
        Cloud[Cloud Misconfig]
        SubTakeover[Subdomain Takeover]
    end

    subgraph Protocol["Headers & Protocol"]
        Redirect[Open Redirect]
        CRLF[CRLF Injection]
        HeaderInj[Header Injection]
    end

    subgraph Analysis["Behavioral Analysis"]
        Context[Context Analyzer]
        Behavior[Behavior Detector]
        OOB[Out-of-Band]
        TechStack[Tech Fingerprinting]
    end
```

## OWASP Framework Mapping

```mermaid
flowchart LR
    Finding["Finding"]

    Finding --> WSTG
    Finding --> Top10
    Finding --> API10

    subgraph WSTG["WSTG v4.2"]
        INFO["INFO - Information Gathering"]
        CONF["CONF - Configuration"]
        IDNT["IDNT - Identity Management"]
        ATHN["ATHN - Authentication"]
        ATHZ["ATHZ - Authorization"]
        SESS["SESS - Session Management"]
        INPV["INPV - Input Validation"]
        ERRH["ERRH - Error Handling"]
        CRYP["CRYP - Cryptography"]
        BUSL["BUSL - Business Logic"]
        CLNT["CLNT - Client-side"]
        APIT["APIT - API Testing"]
    end

    subgraph Top10["OWASP Top 10 2021"]
        A01["A01 - Broken Access Control"]
        A02["A02 - Cryptographic Failures"]
        A03["A03 - Injection"]
        A04["A04 - Insecure Design"]
        A05["A05 - Security Misconfiguration"]
        A06["A06 - Vulnerable Components"]
        A07["A07 - Auth Failures"]
        A08["A08 - Integrity Failures"]
        A09["A09 - Logging Failures"]
        A10["A10 - SSRF"]
    end

    subgraph API10["API Top 10 2023"]
        API1["API1 - Broken Object Level Auth"]
        API2["API2 - Broken Authentication"]
        API3["API3 - Broken Property Auth"]
        API4["API4 - Resource Consumption"]
        API5["API5 - Function Level Auth"]
        API6["API6 - Business Flow Abuse"]
        API7["API7 - SSRF"]
        API8["API8 - Security Misconfig"]
        API9["API9 - Improper Inventory"]
        API10a["API10 - Unsafe API Consumption"]
    end
```

## Output Formats

**Text** (default) - Human-readable report with severity breakdown, finding details, OWASP mappings, and remediation advice.

**JSON** (`--json`) - Structured output with all finding fields for programmatic consumption.

## Project Structure

```
cmd/skws/              Entry point and CLI commands
internal/
  core/                Core types (Finding, Target, EntryPoint, Severity)
  detection/           31 detection modules
  http/                HTTP client with proxy, TLS, and injection support
  owasp/               WSTG, Top 10, API Top 10 mappers
  payloads/            Vulnerability payloads per category
  scanner/             Scan orchestration and concurrency
  templates/           Nuclei-style template engine
  tools/               External tool wrappers (SQLMap, Nuclei, ffuf)
  reporting/           JSON and text report generation
tests/
  integration/         Integration tests (require tool binaries)
  e2e/                 End-to-end scan tests
configs/               Configuration files
data/                  Wordlists and fingerprints
benchmark/             Performance benchmarks
```

## Development

```bash
make build            # Build binary
make test             # Run unit tests
make test-cover       # Tests with coverage report
make test-race        # Tests with race detector
make test-integration # Integration tests
make test-e2e         # End-to-end tests
make lint             # Run golangci-lint
make fmt              # Format code
make vet              # Run go vet
make security         # Run gosec
make check            # All quality gates (fmt, vet, lint, security, test-race)
make bench            # Run benchmarks
```

### Quality Gates

| Gate | Threshold |
|------|-----------|
| Lint | Zero warnings |
| Vet | Zero issues |
| Security (gosec) | Zero high/critical |
| Tests | All pass |
| Coverage | >= 80% |
| Race detector | No races |
