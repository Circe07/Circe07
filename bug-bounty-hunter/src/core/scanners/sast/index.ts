import { execFile } from "child_process";
import { promisify } from "util";
import path from "path";
import fs from "fs/promises";
import { createChildLogger } from "../../../utils/logger";
import { ScanFinding } from "../index";

const execFileAsync = promisify(execFile);
const log = createChildLogger("sast-scanner");

interface SemgrepResult {
  results: SemgrepFinding[];
  errors: SemgrepError[];
}

interface SemgrepFinding {
  check_id: string;
  path: string;
  start: { line: number; col: number };
  end: { line: number; col: number };
  extra: {
    message: string;
    severity: string;
    metadata: Record<string, any>;
    lines: string;
    fix?: string;
  };
}

interface SemgrepError {
  message: string;
  level: string;
}

export class SastScanner {
  private rulesDir: string;

  constructor() {
    this.rulesDir = path.resolve(__dirname, "../../../../rules/semgrep");
  }

  async scan(repoPath: string): Promise<ScanFinding[]> {
    log.info({ repoPath }, "Starting SAST scan with Semgrep");

    const findings: ScanFinding[] = [];

    try {
      const semgrepAvailable = await this.isSemgrepAvailable();
      if (!semgrepAvailable) {
        log.warn("Semgrep not installed, using built-in pattern matching");
        return this.fallbackScan(repoPath);
      }

      const configs = await this.getAvailableConfigs();
      const result = await this.runSemgrep(repoPath, configs);

      for (const finding of result.results) {
        findings.push(this.mapSemgrepFinding(finding, repoPath));
      }

      if (result.errors.length > 0) {
        log.warn(
          { errorCount: result.errors.length },
          "Semgrep reported errors"
        );
      }

      log.info(
        { findingsCount: findings.length },
        "SAST scan complete"
      );
    } catch (err) {
      log.error({ err }, "SAST scan failed");
    }

    return findings;
  }

  private async isSemgrepAvailable(): Promise<boolean> {
    try {
      await execFileAsync("semgrep", ["--version"]);
      return true;
    } catch {
      return false;
    }
  }

  private async getAvailableConfigs(): Promise<string[]> {
    const configs: string[] = [];

    try {
      await fs.access(this.rulesDir);
      configs.push(this.rulesDir);
    } catch {
      // Custom rules not available
    }

    configs.push("p/security-audit");
    configs.push("p/owasp-top-ten");

    return configs;
  }

  private async runSemgrep(
    repoPath: string,
    configs: string[]
  ): Promise<SemgrepResult> {
    const configArgs = configs.flatMap((c) => ["--config", c]);

    try {
      const { stdout } = await execFileAsync(
        "semgrep",
        ["scan", "--json", "--no-git-ignore", ...configArgs, repoPath],
        {
          timeout: 300_000,
          maxBuffer: 50 * 1024 * 1024,
        }
      );

      return JSON.parse(stdout);
    } catch (err: any) {
      if (err.stdout) {
        try {
          return JSON.parse(err.stdout);
        } catch {
          // Parse failed
        }
      }
      throw err;
    }
  }

  private mapSemgrepFinding(
    finding: SemgrepFinding,
    repoPath: string
  ): ScanFinding {
    const severity = this.mapSeverity(finding.extra.severity);
    const cweId = finding.extra.metadata?.cwe?.[0] ?? finding.extra.metadata?.cwe;

    return {
      scanner: "sast",
      vulnerabilityType: this.categorizeVulnerability(finding.check_id),
      severity,
      cweId: typeof cweId === "string" ? cweId : undefined,
      title: `[SAST] ${finding.check_id}`,
      description: finding.extra.message,
      filePath: path.relative(repoPath, finding.path),
      lineNumber: finding.start.line,
      codeSnippet: finding.extra.lines,
      remediation: finding.extra.fix ?? undefined,
      confidence: this.calculateConfidence(finding),
      metadata: {
        checkId: finding.check_id,
        endLine: finding.end.line,
        owasp: finding.extra.metadata?.owasp,
      },
    };
  }

  private mapSeverity(
    semgrepSeverity: string
  ): ScanFinding["severity"] {
    switch (semgrepSeverity.toUpperCase()) {
      case "ERROR":
        return "high";
      case "WARNING":
        return "medium";
      case "INFO":
        return "low";
      default:
        return "info";
    }
  }

  private categorizeVulnerability(checkId: string): string {
    const id = checkId.toLowerCase();
    if (id.includes("sql") && id.includes("injection")) return "SQL Injection";
    if (id.includes("xss")) return "Cross-Site Scripting (XSS)";
    if (id.includes("ssrf")) return "Server-Side Request Forgery (SSRF)";
    if (id.includes("command") && id.includes("injection")) return "Command Injection";
    if (id.includes("path-traversal") || id.includes("path_traversal")) return "Path Traversal";
    if (id.includes("deserial")) return "Insecure Deserialization";
    if (id.includes("crypto") || id.includes("cipher")) return "Weak Cryptography";
    if (id.includes("auth")) return "Authentication Issue";
    if (id.includes("csrf")) return "Cross-Site Request Forgery (CSRF)";
    if (id.includes("redirect")) return "Open Redirect";
    if (id.includes("hardcoded") || id.includes("secret")) return "Hardcoded Secret";
    return "Security Vulnerability";
  }

  private calculateConfidence(finding: SemgrepFinding): number {
    let confidence = 0.5;
    const meta = finding.extra.metadata ?? {};

    if (meta.confidence === "HIGH") confidence += 0.3;
    else if (meta.confidence === "MEDIUM") confidence += 0.15;

    if (finding.extra.severity === "ERROR") confidence += 0.1;
    if (meta.cwe) confidence += 0.05;
    if (meta.owasp) confidence += 0.05;

    return Math.min(confidence, 1.0);
  }

  private async fallbackScan(repoPath: string): Promise<ScanFinding[]> {
    log.info("Running built-in pattern matching (fallback SAST)");
    const findings: ScanFinding[] = [];
    await this.scanDirectory(repoPath, repoPath, findings);
    return findings;
  }

  private async scanDirectory(
    baseDir: string,
    dir: string,
    findings: ScanFinding[]
  ): Promise<void> {
    const entries = await fs.readdir(dir, { withFileTypes: true });

    for (const entry of entries) {
      if (entry.name.startsWith(".") || entry.name === "node_modules") continue;

      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        await this.scanDirectory(baseDir, fullPath, findings);
      } else if (this.isSourceFile(entry.name)) {
        const content = await fs.readFile(fullPath, "utf-8");
        const fileFindings = this.matchPatterns(
          content,
          path.relative(baseDir, fullPath)
        );
        findings.push(...fileFindings);
      }
    }
  }

  private isSourceFile(name: string): boolean {
    const extensions = [
      ".js", ".ts", ".jsx", ".tsx", ".py", ".rb", ".php", ".java", ".go",
      ".cs", ".yml", ".yaml", ".json", ".xml", ".sh", ".bash",
    ];
    return extensions.some((ext) => name.endsWith(ext));
  }

  private matchPatterns(
    content: string,
    filePath: string
  ): ScanFinding[] {
    const findings: ScanFinding[] = [];
    const lines = content.split("\n");

    const PATTERNS: Array<{
      regex: RegExp;
      type: string;
      severity: ScanFinding["severity"];
      cwe: string;
      message: string;
    }> = [
      {
        regex: /(?:query|exec|execute|raw).*\$\{|\$\{.*(?:query|exec|execute|raw)/i,
        type: "SQL Injection",
        severity: "high",
        cwe: "CWE-89",
        message: "Potential SQL injection via string interpolation in database query",
      },
      {
        regex: /eval\s*\(|new\s+Function\s*\(/,
        type: "Code Injection",
        severity: "high",
        cwe: "CWE-94",
        message: "Use of eval() or Function constructor allows arbitrary code execution",
      },
      {
        regex: /innerHTML\s*=|\.html\s*\(|dangerouslySetInnerHTML/,
        type: "Cross-Site Scripting (XSS)",
        severity: "medium",
        cwe: "CWE-79",
        message: "Direct HTML manipulation may lead to XSS if input is not sanitized",
      },
      {
        regex: /child_process.*exec\(|execSync\(|spawn\(/,
        type: "Command Injection",
        severity: "high",
        cwe: "CWE-78",
        message: "Command execution may be vulnerable to injection if input is not sanitized",
      },
      {
        regex: /\.readFile.*req\.|path\.join.*req\.|\.resolve.*req\./,
        type: "Path Traversal",
        severity: "high",
        cwe: "CWE-22",
        message: "File path constructed from user input may allow directory traversal",
      },
      {
        regex: /password\s*[:=]\s*['"][^'"]{3,}['"]/i,
        type: "Hardcoded Secret",
        severity: "medium",
        cwe: "CWE-798",
        message: "Hardcoded password detected in source code",
      },
      {
        regex: /(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['"][^'"]+['"]/i,
        type: "Hardcoded Secret",
        severity: "high",
        cwe: "CWE-798",
        message: "Hardcoded API key or secret token detected",
      },
      {
        regex: /md5|sha1(?![\d])|DES|RC4/i,
        type: "Weak Cryptography",
        severity: "medium",
        cwe: "CWE-327",
        message: "Use of weak or deprecated cryptographic algorithm",
      },
      {
        regex: /cors\(\s*\)|origin:\s*['"]?\*/,
        type: "Misconfiguration",
        severity: "medium",
        cwe: "CWE-942",
        message: "Permissive CORS configuration allows requests from any origin",
      },
      {
        regex: /pickle\.loads|yaml\.load\s*\((?!.*Loader)/,
        type: "Insecure Deserialization",
        severity: "high",
        cwe: "CWE-502",
        message: "Insecure deserialization may allow arbitrary code execution",
      },
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.trim().startsWith("//") || line.trim().startsWith("#")) continue;

      for (const pattern of PATTERNS) {
        if (pattern.regex.test(line)) {
          findings.push({
            scanner: "sast",
            vulnerabilityType: pattern.type,
            severity: pattern.severity,
            cweId: pattern.cwe,
            title: `[SAST] ${pattern.type} in ${filePath}`,
            description: pattern.message,
            filePath,
            lineNumber: i + 1,
            codeSnippet: line.trim(),
            confidence: 0.4,
          });
        }
      }
    }

    return findings;
  }
}
