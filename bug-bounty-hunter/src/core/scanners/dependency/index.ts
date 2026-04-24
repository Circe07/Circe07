import { execFile } from "child_process";
import { promisify } from "util";
import fs from "fs/promises";
import path from "path";
import axios from "axios";
import { createChildLogger } from "../../../utils/logger";
import { ScanFinding } from "../index";

const execFileAsync = promisify(execFile);
const log = createChildLogger("dependency-scanner");

const OSV_API = "https://api.osv.dev/v1";

interface OsvVulnerability {
  id: string;
  summary: string;
  details: string;
  severity: Array<{ type: string; score: string }>;
  affected: Array<{
    package: { name: string; ecosystem: string };
    ranges: Array<{
      type: string;
      events: Array<{ introduced?: string; fixed?: string }>;
    }>;
  }>;
  references: Array<{ type: string; url: string }>;
  database_specific?: Record<string, any>;
}

export class DependencyScanner {
  async scan(repoPath: string): Promise<ScanFinding[]> {
    log.info({ repoPath }, "Starting dependency scan");

    const findings: ScanFinding[] = [];

    const lockFiles = await this.detectLockFiles(repoPath);

    for (const lockFile of lockFiles) {
      try {
        const deps = await this.parseDependencies(lockFile, repoPath);
        const vulns = await this.queryOsv(deps, lockFile.ecosystem);

        for (const vuln of vulns) {
          findings.push(
            this.mapVulnerability(vuln, lockFile.file, repoPath)
          );
        }
      } catch (err) {
        log.error(
          { err, file: lockFile.file },
          "Dependency scan failed for file"
        );
      }
    }

    log.info(
      { findingsCount: findings.length },
      "Dependency scan complete"
    );
    return findings;
  }

  private async detectLockFiles(
    repoPath: string
  ): Promise<Array<{ file: string; ecosystem: string }>> {
    const lockFileMap: Record<string, string> = {
      "package-lock.json": "npm",
      "yarn.lock": "npm",
      "pnpm-lock.yaml": "npm",
      "package.json": "npm",
      "requirements.txt": "PyPI",
      "Pipfile.lock": "PyPI",
      "poetry.lock": "PyPI",
      "Gemfile.lock": "RubyGems",
      "go.sum": "Go",
      "Cargo.lock": "crates.io",
      "pom.xml": "Maven",
      "build.gradle": "Maven",
      "composer.lock": "Packagist",
    };

    const found: Array<{ file: string; ecosystem: string }> = [];

    for (const [file, ecosystem] of Object.entries(lockFileMap)) {
      const filePath = path.join(repoPath, file);
      try {
        await fs.access(filePath);
        found.push({ file, ecosystem });
      } catch {
        // File not found
      }
    }

    log.info(
      { lockFiles: found.map((f) => f.file) },
      "Detected dependency files"
    );
    return found;
  }

  private async parseDependencies(
    lockFile: { file: string; ecosystem: string },
    repoPath: string
  ): Promise<Array<{ name: string; version: string }>> {
    const filePath = path.join(repoPath, lockFile.file);
    const content = await fs.readFile(filePath, "utf-8");

    switch (lockFile.file) {
      case "package.json":
        return this.parsePackageJson(content);
      case "requirements.txt":
        return this.parseRequirementsTxt(content);
      default:
        return this.parsePackageJson(content);
    }
  }

  private parsePackageJson(
    content: string
  ): Array<{ name: string; version: string }> {
    try {
      const pkg = JSON.parse(content);
      const deps: Array<{ name: string; version: string }> = [];

      for (const [name, version] of Object.entries(pkg.dependencies ?? {})) {
        deps.push({
          name,
          version: String(version).replace(/^[\^~>=<]+/, ""),
        });
      }
      for (const [name, version] of Object.entries(pkg.devDependencies ?? {})) {
        deps.push({
          name,
          version: String(version).replace(/^[\^~>=<]+/, ""),
        });
      }

      return deps;
    } catch {
      return [];
    }
  }

  private parseRequirementsTxt(
    content: string
  ): Array<{ name: string; version: string }> {
    const deps: Array<{ name: string; version: string }> = [];

    for (const line of content.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("-")) continue;

      const match = trimmed.match(/^([a-zA-Z0-9_-]+)\s*(?:==|>=|~=)\s*(.+)/);
      if (match) {
        deps.push({ name: match[1], version: match[2].trim() });
      }
    }

    return deps;
  }

  private async queryOsv(
    deps: Array<{ name: string; version: string }>,
    ecosystem: string
  ): Promise<OsvVulnerability[]> {
    const vulnerabilities: OsvVulnerability[] = [];

    const batchSize = 100;
    for (let i = 0; i < deps.length; i += batchSize) {
      const batch = deps.slice(i, i + batchSize);
      const queries = batch.map((dep) => ({
        package: { name: dep.name, ecosystem },
        version: dep.version,
      }));

      try {
        const response = await axios.post(
          `${OSV_API}/querybatch`,
          { queries },
          { timeout: 30_000 }
        );

        const results = response.data?.results ?? [];
        for (const result of results) {
          for (const vuln of result.vulns ?? []) {
            vulnerabilities.push(vuln);
          }
        }
      } catch (err) {
        log.error({ err }, "OSV API query failed");
      }
    }

    return vulnerabilities;
  }

  private mapVulnerability(
    vuln: OsvVulnerability,
    sourceFile: string,
    repoPath: string
  ): ScanFinding {
    const severity = this.mapOsvSeverity(vuln);
    const cvssScore = this.extractCvss(vuln);
    const packageName =
      vuln.affected?.[0]?.package?.name ?? "unknown";

    return {
      scanner: "dependency",
      vulnerabilityType: "Vulnerable Dependency",
      severity,
      cvssScore,
      cweId: undefined,
      title: `[DEP] ${vuln.id}: ${vuln.summary ?? packageName}`,
      description: vuln.details ?? vuln.summary ?? "",
      filePath: sourceFile,
      confidence: 0.85,
      remediation: this.getRemediationAdvice(vuln),
      metadata: {
        osvId: vuln.id,
        packageName,
        references: vuln.references?.map((r) => r.url),
      },
    };
  }

  private mapOsvSeverity(vuln: OsvVulnerability): ScanFinding["severity"] {
    const cvss = this.extractCvss(vuln);
    if (cvss === undefined) return "medium";
    if (cvss >= 9.0) return "critical";
    if (cvss >= 7.0) return "high";
    if (cvss >= 4.0) return "medium";
    if (cvss >= 0.1) return "low";
    return "info";
  }

  private extractCvss(vuln: OsvVulnerability): number | undefined {
    const cvssEntry = vuln.severity?.find(
      (s) => s.type === "CVSS_V3" || s.type === "CVSS_V2"
    );
    if (!cvssEntry) return undefined;
    const score = parseFloat(cvssEntry.score);
    return isNaN(score) ? undefined : score;
  }

  private getRemediationAdvice(vuln: OsvVulnerability): string {
    const fixedVersions: string[] = [];
    for (const affected of vuln.affected ?? []) {
      for (const range of affected.ranges ?? []) {
        for (const event of range.events ?? []) {
          if (event.fixed) fixedVersions.push(event.fixed);
        }
      }
    }

    if (fixedVersions.length > 0) {
      return `Update to version ${fixedVersions.join(" or ")} to fix this vulnerability.`;
    }

    return "Check the vulnerability database for available patches or alternative packages.";
  }
}
