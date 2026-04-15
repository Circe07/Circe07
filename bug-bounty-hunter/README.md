# BugBountyHunter

Automated security vulnerability discovery system for Bug Bounty programs.

## Features

- **Target Discovery** - Automatically find bug bounty programs on HackerOne, Bugcrowd, and GitHub
- **SAST Scanner** - Static analysis using Semgrep + built-in pattern matching fallback
- **Dependency Scanner** - CVE detection using OSV database (npm, PyPI, Go, Cargo, Maven, Composer, RubyGems)
- **Secret Scanner** - Detect exposed API keys, tokens, and credentials (with TruffleHog integration + 14 regex patterns)
- **Misconfiguration Scanner** - Docker, Kubernetes, Terraform, GitHub Actions, CORS, npm hooks
- **AI Triage** - Confidence scoring, SHA-256 deduplication, reachability analysis, and bounty estimation
- **Report Generator** - Platform-specific vulnerability reports (HackerOne, Bugcrowd, Generic)
- **Full Pipeline** - End-to-end: discover targets -> scan -> triage -> report
- **API Server** - Fastify REST API for programmatic access
- **Job Queue** - BullMQ-based async job processing for scans, discovery, and reports

## Quick Start

```bash
# Install dependencies
npm install

# Copy environment configuration
cp .env.example .env
# Edit .env with your GitHub token and API keys

# Start infrastructure (PostgreSQL + Redis)
docker-compose up -d

# Run database migrations
npx prisma migrate dev

# Scan a repository
npx tsx src/cli.ts scan --repo https://github.com/org/repo

# Run full pipeline
npx tsx src/cli.ts pipeline --platforms github --max-targets 5
```

## CLI Commands

```bash
# Discover bug bounty programs
bbhunter discover --platforms hackerone,bugcrowd,github --max 50

# Scan a specific repository
bbhunter scan --repo <url> --scanners sast,dependency,secrets,misconfig

# Scan and triage with bounty estimates
bbhunter triage --repo <url> --threshold 0.6

# Generate reports (saved to disk)
bbhunter report --repo <url> --platform hackerone --output ./reports

# Full automated pipeline
bbhunter pipeline --platforms github --max-targets 10

# Start the API server
bbhunter serve --port 3000
```

## API Endpoints

```
GET  /health          - Health check
GET  /ready           - Readiness check
GET  /api/scanners    - List available scanners
POST /api/scan        - Scan a repository
POST /api/discover    - Discover bug bounty targets
```

## Semgrep Rules

Custom rules included for:
- **JavaScript/TypeScript** - SQL Injection, Command Injection, XSS, NoSQL Injection, Path Traversal, eval()
- **Python** - SQL Injection, Command Injection, Pickle, YAML unsafe load, SSRF
- **Go** - SQL Injection, Command Injection, SSRF, Path Traversal, Weak Crypto
- **Java** - SQL Injection, Command Injection, XXE, Deserialization, JNDI Injection, Weak Crypto

## Architecture

See [PLAN.md](./PLAN.md) for the complete architecture, module details, and development roadmap.

## Testing

```bash
npm test              # Run all tests (36 tests, 6 suites)
npm run test:watch    # Watch mode
```

## Tech Stack

- **Runtime:** Node.js 20+ with TypeScript (strict mode)
- **API:** Fastify
- **SAST:** Semgrep + custom pattern matching fallback
- **Dependencies:** OSV-Scanner API (multi-ecosystem)
- **Secrets:** TruffleHog + regex patterns
- **Database:** PostgreSQL with Prisma ORM
- **Queue:** BullMQ + Redis
- **CLI:** Commander.js
- **Testing:** Vitest
- **Validation:** Zod
- **Logging:** Pino

## Legal & Ethical

This tool is designed for **authorized security research only**. Always:

1. Only scan public repositories
2. Respect bug bounty program scope
3. Follow responsible disclosure practices
4. Never exploit found vulnerabilities
5. Comply with all applicable laws and platform terms of service

## License

MIT
