import fs from "fs/promises";
import path from "path";
import { createChildLogger } from "../../../utils/logger";
import { ScanFinding } from "../index";

const log = createChildLogger("misconfig-scanner");

interface MisconfigRule {
  id: string;
  name: string;
  description: string;
  severity: ScanFinding["severity"];
  cweId: string;
  filePatterns: string[];
  check: (content: string, filePath: string) => MisconfigMatch[];
}

interface MisconfigMatch {
  message: string;
  lineNumber?: number;
  codeSnippet?: string;
}

export class MisconfigScanner {
  private rules: MisconfigRule[];

  constructor() {
    this.rules = this.buildRules();
  }

  async scan(repoPath: string): Promise<ScanFinding[]> {
    log.info({ repoPath }, "Starting misconfiguration scan");
    const findings: ScanFinding[] = [];

    const files = await this.collectFiles(repoPath, repoPath);

    for (const file of files) {
      const relativePath = path.relative(repoPath, file.path);
      const applicableRules = this.rules.filter((rule) =>
        rule.filePatterns.some((pattern) =>
          this.matchesPattern(file.name, pattern)
        )
      );

      if (applicableRules.length === 0) continue;

      try {
        const content = await fs.readFile(file.path, "utf-8");

        for (const rule of applicableRules) {
          const matches = rule.check(content, relativePath);
          for (const match of matches) {
            findings.push({
              scanner: "misconfig",
              vulnerabilityType: "Misconfiguration",
              severity: rule.severity,
              cweId: rule.cweId,
              title: `[MISCONFIG] ${rule.name} in ${relativePath}`,
              description: `${rule.description}\n\n${match.message}`,
              filePath: relativePath,
              lineNumber: match.lineNumber,
              codeSnippet: match.codeSnippet,
              confidence: 0.7,
            });
          }
        }
      } catch {
        // Skip unreadable files
      }
    }

    log.info(
      { findingsCount: findings.length },
      "Misconfiguration scan complete"
    );
    return findings;
  }

  private async collectFiles(
    baseDir: string,
    dir: string
  ): Promise<Array<{ path: string; name: string }>> {
    const results: Array<{ path: string; name: string }> = [];

    try {
      const entries = await fs.readdir(dir, { withFileTypes: true });

      for (const entry of entries) {
        if (entry.name === "node_modules" || entry.name === ".git") continue;

        const fullPath = path.join(dir, entry.name);

        if (entry.isDirectory()) {
          const sub = await this.collectFiles(baseDir, fullPath);
          results.push(...sub);
        } else {
          results.push({ path: fullPath, name: entry.name });
        }
      }
    } catch {
      // Skip inaccessible directories
    }

    return results;
  }

  private matchesPattern(fileName: string, pattern: string): boolean {
    if (pattern.startsWith("*")) {
      return fileName.endsWith(pattern.slice(1));
    }
    return fileName === pattern || fileName.toLowerCase() === pattern.toLowerCase();
  }

  private buildRules(): MisconfigRule[] {
    return [
      {
        id: "docker-root-user",
        name: "Docker Container Running as Root",
        description: "Dockerfile does not specify a non-root user. Containers should not run as root.",
        severity: "medium",
        cweId: "CWE-250",
        filePatterns: ["Dockerfile", "*.dockerfile"],
        check: (content) => {
          if (!content.includes("USER ") || content.includes("USER root")) {
            return [{ message: "No non-root USER directive found in Dockerfile" }];
          }
          return [];
        },
      },
      {
        id: "docker-secret-in-env",
        name: "Secret in Docker ENV",
        description: "Dockerfile contains secrets in ENV instructions, which are visible in image layers.",
        severity: "high",
        cweId: "CWE-798",
        filePatterns: ["Dockerfile", "*.dockerfile"],
        check: (content) => {
          const matches: MisconfigMatch[] = [];
          const lines = content.split("\n");
          for (let i = 0; i < lines.length; i++) {
            if (/^ENV\s+.*(?:PASSWORD|SECRET|TOKEN|KEY|API_KEY)/i.test(lines[i])) {
              matches.push({
                message: "Secret exposed in Docker ENV instruction",
                lineNumber: i + 1,
                codeSnippet: lines[i].trim(),
              });
            }
          }
          return matches;
        },
      },
      {
        id: "github-actions-injection",
        name: "GitHub Actions Script Injection",
        description: "GitHub Actions workflow uses potentially injectable expressions in run steps.",
        severity: "high",
        cweId: "CWE-78",
        filePatterns: ["*.yml", "*.yaml"],
        check: (content, filePath) => {
          if (!filePath.includes(".github/workflows")) return [];
          const matches: MisconfigMatch[] = [];
          const lines = content.split("\n");
          for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            if (
              line.includes("run:") &&
              /\$\{\{\s*github\.event\.(issue|pull_request|comment)/.test(
                lines.slice(i, i + 5).join("\n")
              )
            ) {
              matches.push({
                message: "User-controlled GitHub event data used in run step (potential command injection)",
                lineNumber: i + 1,
                codeSnippet: line.trim(),
              });
            }
          }
          return matches;
        },
      },
      {
        id: "github-actions-permissions",
        name: "GitHub Actions Overly Permissive",
        description: "GitHub Actions workflow has overly permissive write-all permissions.",
        severity: "medium",
        cweId: "CWE-250",
        filePatterns: ["*.yml", "*.yaml"],
        check: (content, filePath) => {
          if (!filePath.includes(".github/workflows")) return [];
          if (content.includes("permissions: write-all")) {
            return [{ message: "Workflow uses write-all permissions, violating least-privilege" }];
          }
          return [];
        },
      },
      {
        id: "cors-wildcard",
        name: "Permissive CORS Configuration",
        description: "Application allows CORS requests from any origin.",
        severity: "medium",
        cweId: "CWE-942",
        filePatterns: ["*.ts", "*.js", "*.json", "*.py"],
        check: (content) => {
          const matches: MisconfigMatch[] = [];
          const lines = content.split("\n");
          for (let i = 0; i < lines.length; i++) {
            if (
              /cors\(\s*\)/.test(lines[i]) ||
              /origin:\s*['"]?\*['"]?/.test(lines[i]) ||
              /Access-Control-Allow-Origin.*\*/.test(lines[i])
            ) {
              matches.push({
                message: "CORS configured to allow all origins",
                lineNumber: i + 1,
                codeSnippet: lines[i].trim(),
              });
            }
          }
          return matches;
        },
      },
      {
        id: "terraform-s3-public",
        name: "Public S3 Bucket",
        description: "Terraform S3 bucket is configured with public access.",
        severity: "high",
        cweId: "CWE-284",
        filePatterns: ["*.tf"],
        check: (content) => {
          const matches: MisconfigMatch[] = [];
          if (/acl\s*=\s*"public-read"/.test(content)) {
            matches.push({ message: "S3 bucket configured with public-read ACL" });
          }
          if (/block_public_acls\s*=\s*false/.test(content)) {
            matches.push({ message: "S3 public access block disabled" });
          }
          return matches;
        },
      },
      {
        id: "k8s-privileged-container",
        name: "Privileged Kubernetes Container",
        description: "Kubernetes manifest runs container in privileged mode.",
        severity: "high",
        cweId: "CWE-250",
        filePatterns: ["*.yml", "*.yaml"],
        check: (content) => {
          if (
            content.includes("kind: Pod") ||
            content.includes("kind: Deployment") ||
            content.includes("kind: StatefulSet")
          ) {
            if (/privileged:\s*true/.test(content)) {
              return [{ message: "Container running in privileged mode" }];
            }
          }
          return [];
        },
      },
      {
        id: "npm-postinstall-script",
        name: "Suspicious npm Post-Install Script",
        description: "package.json has a postinstall script that could be malicious.",
        severity: "medium",
        cweId: "CWE-506",
        filePatterns: ["package.json"],
        check: (content) => {
          try {
            const pkg = JSON.parse(content);
            const scripts = pkg.scripts ?? {};
            const suspicious = ["postinstall", "preinstall", "install"];
            const matches: MisconfigMatch[] = [];
            for (const hook of suspicious) {
              if (scripts[hook]) {
                const cmd = scripts[hook];
                if (/curl|wget|eval|bash|sh -c|node -e/.test(cmd)) {
                  matches.push({
                    message: `Suspicious ${hook} script: ${cmd}`,
                  });
                }
              }
            }
            return matches;
          } catch {
            return [];
          }
        },
      },
    ];
  }
}
