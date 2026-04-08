import { createChildLogger } from "../../utils/logger";
import { SastScanner } from "./sast";
import { DependencyScanner } from "./dependency";
import { SecretScanner } from "./secrets";
import { MisconfigScanner } from "./misconfig";

const log = createChildLogger("scanner-orchestrator");

export interface ScanResult {
  scanner: string;
  findings: ScanFinding[];
  duration: number;
  error?: string;
}

export interface ScanFinding {
  scanner: string;
  vulnerabilityType: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  cvssScore?: number;
  cweId?: string;
  title: string;
  description: string;
  filePath?: string;
  lineNumber?: number;
  codeSnippet?: string;
  remediation?: string;
  confidence: number;
  metadata?: Record<string, unknown>;
}

export interface ScanOptions {
  scanners?: ("sast" | "dependency" | "secrets" | "misconfig")[];
  severityThreshold?: "critical" | "high" | "medium" | "low" | "info";
  maxFindings?: number;
}

export async function runAllScanners(
  repoPath: string,
  options: ScanOptions = {}
): Promise<ScanResult[]> {
  const scanners = options.scanners ?? [
    "sast",
    "dependency",
    "secrets",
    "misconfig",
  ];

  log.info({ repoPath, scanners }, "Starting scan pipeline");

  const results: ScanResult[] = [];

  const scannerMap: Record<string, () => Promise<ScanResult>> = {
    sast: () => runScanner("sast", () => new SastScanner().scan(repoPath)),
    dependency: () =>
      runScanner("dependency", () =>
        new DependencyScanner().scan(repoPath)
      ),
    secrets: () =>
      runScanner("secrets", () => new SecretScanner().scan(repoPath)),
    misconfig: () =>
      runScanner("misconfig", () =>
        new MisconfigScanner().scan(repoPath)
      ),
  };

  const tasks = scanners
    .filter((s) => scannerMap[s])
    .map((s) => scannerMap[s]());

  const settled = await Promise.allSettled(tasks);

  for (const result of settled) {
    if (result.status === "fulfilled") {
      results.push(result.value);
    } else {
      log.error({ err: result.reason }, "Scanner failed");
    }
  }

  const totalFindings = results.reduce(
    (sum, r) => sum + r.findings.length,
    0
  );

  log.info(
    { totalFindings, scanners: results.map((r) => r.scanner) },
    "Scan pipeline complete"
  );

  return results;
}

async function runScanner(
  name: string,
  fn: () => Promise<ScanFinding[]>
): Promise<ScanResult> {
  const start = Date.now();
  try {
    const findings = await fn();
    return {
      scanner: name,
      findings,
      duration: Date.now() - start,
    };
  } catch (err: any) {
    log.error({ err, scanner: name }, "Scanner execution failed");
    return {
      scanner: name,
      findings: [],
      duration: Date.now() - start,
      error: err.message,
    };
  }
}

const SEVERITY_ORDER = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export function filterBySeverity(
  findings: ScanFinding[],
  threshold: keyof typeof SEVERITY_ORDER
): ScanFinding[] {
  const minLevel = SEVERITY_ORDER[threshold];
  return findings.filter(
    (f) => SEVERITY_ORDER[f.severity] >= minLevel
  );
}

export function sortByPriority(findings: ScanFinding[]): ScanFinding[] {
  return [...findings].sort((a, b) => {
    const sevDiff =
      SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
    if (sevDiff !== 0) return sevDiff;
    return b.confidence - a.confidence;
  });
}
