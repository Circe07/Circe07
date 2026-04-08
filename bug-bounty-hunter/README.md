# BugBountyHunter

Automated security vulnerability discovery system for Bug Bounty programs.

## Features

- **Target Discovery** - Automatically find bug bounty programs on HackerOne, Bugcrowd, and GitHub
- **SAST Scanner** - Static analysis using Semgrep + built-in pattern matching
- **Dependency Scanner** - CVE detection using OSV database
- **Secret Scanner** - Detect exposed API keys, tokens, and credentials (with TruffleHog integration)
- **Misconfiguration Scanner** - Docker, Kubernetes, Terraform, GitHub Actions security checks
- **AI Triage** - Confidence scoring, deduplication, and bounty estimation
- **Report Generator** - Platform-specific vulnerability reports (HackerOne, Bugcrowd)
- **Full Pipeline** - End-to-end: discover targets -> scan -> triage -> report

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
npx tsx src/cli.ts discover --platforms hackerone,bugcrowd,github

# Scan a specific repository
npx tsx src/cli.ts scan --repo <url> --scanners sast,dependency,secrets,misconfig

# Scan and triage with bounty estimates
npx tsx src/cli.ts triage --repo <url> --threshold 0.6

# Generate reports
npx tsx src/cli.ts report --repo <url> --platform hackerone

# Full automated pipeline
npx tsx src/cli.ts pipeline --platforms github --max-targets 10
```

## Architecture

See [PLAN.md](./PLAN.md) for the complete architecture, module details, and development roadmap.

## Testing

```bash
npm test              # Run all tests
npm run test:watch    # Watch mode
```

## Tech Stack

- **Runtime:** Node.js 20+ with TypeScript
- **SAST:** Semgrep + custom pattern matching
- **Dependencies:** OSV-Scanner API
- **Secrets:** TruffleHog + regex patterns
- **Database:** PostgreSQL with Prisma ORM
- **Queue:** BullMQ + Redis
- **CLI:** Commander.js

## Legal & Ethical

This tool is designed for **authorized security research only**. Always:

1. Only scan public repositories
2. Respect bug bounty program scope
3. Follow responsible disclosure practices
4. Never exploit found vulnerabilities
5. Comply with all applicable laws and platform terms of service

## License

MIT
