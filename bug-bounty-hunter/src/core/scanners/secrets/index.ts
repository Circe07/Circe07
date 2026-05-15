import fs from "fs/promises";
import path from "path";
import { execFile } from "child_process";
import { promisify } from "util";
import { createChildLogger } from "../../../utils/logger";
import { ScanFinding } from "../index";

const execFileAsync = promisify(execFile);
const log = createChildLogger("secret-scanner");

interface SecretPattern {
  name: string;
  regex: RegExp;
  severity: ScanFinding["severity"];
  description: string;
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: "AWS Access Key",
    regex: /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/,
    severity: "critical",
    description: "AWS Access Key ID found in source code",
  },
  {
    name: "AWS Secret Key",
    regex: /(?:aws)?_?(?:secret)?_?(?:access)?_?(?:key)?.*?[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/i,
    severity: "critical",
    description: "AWS Secret Access Key found in source code",
  },
  {
    name: "GitHub Token",
    regex: /gh[pousr]_[A-Za-z0-9_]{36,255}/,
    severity: "critical",
    description: "GitHub personal access token or OAuth token found",
  },
  {
    name: "GitLab Token",
    regex: /glpat-[A-Za-z0-9\-_]{20,}/,
    severity: "critical",
    description: "GitLab personal access token found",
  },
  {
    name: "Stripe Key",
    regex: new RegExp("(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{20,}"),
    severity: "high",
    description: "Stripe API key found in source code",
  },
  {
    name: "Twilio Auth Token",
    regex: /SK[a-f0-9]{32}/,
    severity: "high",
    description: "Twilio API key found",
  },
  {
    name: "SendGrid Key",
    regex: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/,
    severity: "high",
    description: "SendGrid API key found",
  },
  {
    name: "Slack Token",
    regex: /xox[baprs]-[0-9]{12}-[0-9]{12,13}-[a-zA-Z0-9]{24,}/,
    severity: "high",
    description: "Slack API token found",
  },
  {
    name: "Google API Key",
    regex: /AIza[0-9A-Za-z_-]{35}/,
    severity: "high",
    description: "Google API key found",
  },
  {
    name: "Private Key",
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
    severity: "critical",
    description: "Private key found in source code",
  },
  {
    name: "JWT Token",
    regex: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/,
    severity: "medium",
    description: "JWT token found (may be a test token or an exposed real token)",
  },
  {
    name: "Database URL",
    regex: /(?:postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@[^/\s]+/i,
    severity: "high",
    description: "Database connection string with credentials found",
  },
  {
    name: "Generic API Key",
    regex: /(?:api[_-]?key|apikey)\s*[:=]\s*['"]([A-Za-z0-9_\-]{20,})['"]?/i,
    severity: "medium",
    description: "Generic API key pattern found",
  },
  {
    name: "Generic Secret",
    regex: /(?:secret|token|password|passwd|pwd)\s*[:=]\s*['"]([A-Za-z0-9_\-!@#$%^&*]{8,})['"]?/i,
    severity: "medium",
    description: "Potential secret or password hardcoded in source",
  },
];

const IGNORE_PATHS = [
  "node_modules",
  ".git",
  "vendor",
  "__pycache__",
  ".next",
  "dist",
  "build",
  "coverage",
  ".venv",
  "venv",
];

const IGNORE_EXTENSIONS = [
  ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
  ".ttf", ".eot", ".mp4", ".mp3", ".pdf", ".zip", ".tar", ".gz",
  ".lock", ".min.js", ".min.css", ".map",
];

export class SecretScanner {
  async scan(repoPath: string): Promise<ScanFinding[]> {
    log.info({ repoPath }, "Starting secret scan");
    const findings: ScanFinding[] = [];

    const truffleHogAvailable = await this.isTruffleHogAvailable();

    if (truffleHogAvailable) {
      const thFindings = await this.runTruffleHog(repoPath);
      findings.push(...thFindings);
    }

    const patternFindings = await this.runPatternScan(repoPath, repoPath);
    findings.push(...patternFindings);

    const deduplicated = this.deduplicateFindings(findings);
    log.info(
      { findingsCount: deduplicated.length },
      "Secret scan complete"
    );
    return deduplicated;
  }

  private async isTruffleHogAvailable(): Promise<boolean> {
    try {
      await execFileAsync("trufflehog", ["--version"]);
      return true;
    } catch {
      return false;
    }
  }

  private async runTruffleHog(repoPath: string): Promise<ScanFinding[]> {
    const findings: ScanFinding[] = [];

    try {
      const { stdout } = await execFileAsync(
        "trufflehog",
        ["filesystem", "--json", "--no-update", repoPath],
        { timeout: 300_000, maxBuffer: 50 * 1024 * 1024 }
      );

      for (const line of stdout.split("\n").filter(Boolean)) {
        try {
          const result = JSON.parse(line);
          findings.push({
            scanner: "secrets",
            vulnerabilityType: "Exposed Secret",
            severity: "high",
            title: `[SECRET] ${result.DetectorName ?? "Secret"} found`,
            description: `${result.DetectorName ?? "Secret"} detected by TruffleHog`,
            filePath: result.SourceMetadata?.Data?.Filesystem?.file,
            lineNumber: result.SourceMetadata?.Data?.Filesystem?.line,
            codeSnippet: result.Raw ? "[REDACTED]" : undefined,
            confidence: result.Verified ? 0.95 : 0.7,
            cweId: "CWE-798",
            metadata: {
              detector: result.DetectorName,
              verified: result.Verified,
              decoderName: result.DecoderName,
            },
          });
        } catch {
          // Skip unparseable lines
        }
      }
    } catch (err) {
      log.error({ err }, "TruffleHog scan failed");
    }

    return findings;
  }

  private async runPatternScan(
    baseDir: string,
    dir: string
  ): Promise<ScanFinding[]> {
    const findings: ScanFinding[] = [];

    try {
      const entries = await fs.readdir(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);

        if (IGNORE_PATHS.includes(entry.name)) continue;
        if (entry.name.startsWith(".") && entry.name !== ".env") continue;

        if (entry.isDirectory()) {
          const subFindings = await this.runPatternScan(baseDir, fullPath);
          findings.push(...subFindings);
        } else if (this.shouldScanFile(entry.name)) {
          const fileFindings = await this.scanFile(baseDir, fullPath);
          findings.push(...fileFindings);
        }
      }
    } catch (err) {
      log.error({ err, dir }, "Pattern scan failed for directory");
    }

    return findings;
  }

  private shouldScanFile(name: string): boolean {
    return !IGNORE_EXTENSIONS.some((ext) =>
      name.toLowerCase().endsWith(ext)
    );
  }

  private async scanFile(
    baseDir: string,
    filePath: string
  ): Promise<ScanFinding[]> {
    const findings: ScanFinding[] = [];

    try {
      const stat = await fs.stat(filePath);
      if (stat.size > 1_000_000) return findings; // Skip files > 1MB

      const content = await fs.readFile(filePath, "utf-8");
      const lines = content.split("\n");
      const relativePath = path.relative(baseDir, filePath);

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.trim().startsWith("//") && line.includes("example")) continue;

        for (const pattern of SECRET_PATTERNS) {
          if (pattern.regex.test(line)) {
            if (this.isLikelyFalsePositive(line, relativePath)) continue;

            findings.push({
              scanner: "secrets",
              vulnerabilityType: "Exposed Secret",
              severity: pattern.severity,
              cweId: "CWE-798",
              title: `[SECRET] ${pattern.name} in ${relativePath}`,
              description: pattern.description,
              filePath: relativePath,
              lineNumber: i + 1,
              codeSnippet: this.redactSecret(line.trim()),
              confidence: this.calculateConfidence(relativePath, line),
            });
          }
        }
      }
    } catch {
      // Skip unreadable files
    }

    return findings;
  }

  private isLikelyFalsePositive(line: string, filePath: string): boolean {
    const fp = filePath.toLowerCase();
    if (fp.includes("test") || fp.includes("mock") || fp.includes("fixture")) return true;
    if (fp.includes("example") || fp.includes("sample") || fp.includes("template")) return true;

    const lower = line.toLowerCase();
    if (lower.includes("example") || lower.includes("placeholder")) return true;
    if (lower.includes("your_") || lower.includes("xxx")) return true;
    if (lower.includes("todo") || lower.includes("fixme")) return true;

    return false;
  }

  private redactSecret(line: string): string {
    return line.replace(
      /(['"])([A-Za-z0-9_\-/+=]{8,})\1/g,
      (_, quote) => `${quote}[REDACTED]${quote}`
    );
  }

  private calculateConfidence(filePath: string, line: string): number {
    let confidence = 0.5;

    if (filePath.endsWith(".env") || filePath.includes(".env.")) confidence += 0.2;
    if (filePath.includes("config") || filePath.includes("settings")) confidence += 0.1;
    if (filePath.includes("prod") || filePath.includes("production")) confidence += 0.15;

    if (/^[A-Z_]+\s*=/.test(line.trim())) confidence += 0.1;

    return Math.min(confidence, 1.0);
  }

  private deduplicateFindings(findings: ScanFinding[]): ScanFinding[] {
    const seen = new Set<string>();
    return findings.filter((f) => {
      const key = `${f.filePath}:${f.lineNumber}:${f.vulnerabilityType}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }
}
