import { ScanFinding } from "../scanners";
import { createChildLogger } from "../../utils/logger";

const log = createChildLogger("scorer");

export interface ScoredFinding extends ScanFinding {
  finalScore: number;
  bountyEstimate: number;
  severityScore: number;
  confidenceScore: number;
  reachabilityScore: number;
  noveltyScore: number;
}

const SEVERITY_SCORES: Record<string, number> = {
  critical: 1.0,
  high: 0.8,
  medium: 0.5,
  low: 0.25,
  info: 0.1,
};

const BOUNTY_ESTIMATES: Record<string, { min: number; max: number }> = {
  critical: { min: 5000, max: 50000 },
  high: { min: 1000, max: 10000 },
  medium: { min: 200, max: 2000 },
  low: { min: 50, max: 500 },
  info: { min: 0, max: 100 },
};

const VULN_TYPE_MULTIPLIERS: Record<string, number> = {
  "SQL Injection": 1.3,
  "Command Injection": 1.4,
  "Server-Side Request Forgery (SSRF)": 1.2,
  "Insecure Deserialization": 1.3,
  "Path Traversal": 1.1,
  "Exposed Secret": 1.5,
  "Cross-Site Scripting (XSS)": 0.9,
  "Vulnerable Dependency": 0.7,
  "Misconfiguration": 0.6,
  "Weak Cryptography": 0.5,
  "Hardcoded Secret": 1.2,
};

const WEIGHTS = {
  severity: 0.3,
  confidence: 0.25,
  reachability: 0.2,
  bountyEstimate: 0.15,
  novelty: 0.1,
};

export function scoreFindings(findings: ScanFinding[]): ScoredFinding[] {
  return findings.map(scoreSingleFinding);
}

function scoreSingleFinding(finding: ScanFinding): ScoredFinding {
  const severityScore = SEVERITY_SCORES[finding.severity] ?? 0.1;
  const confidenceScore = finding.confidence;
  const reachabilityScore = estimateReachability(finding);
  const noveltyScore = estimateNovelty(finding);
  const bountyEstimate = estimateBounty(finding);
  const normalizedBounty = Math.min(bountyEstimate / 10000, 1.0);

  const finalScore =
    severityScore * WEIGHTS.severity +
    confidenceScore * WEIGHTS.confidence +
    reachabilityScore * WEIGHTS.reachability +
    normalizedBounty * WEIGHTS.bountyEstimate +
    noveltyScore * WEIGHTS.novelty;

  return {
    ...finding,
    finalScore: Math.round(finalScore * 100) / 100,
    bountyEstimate: Math.round(bountyEstimate),
    severityScore,
    confidenceScore,
    reachabilityScore,
    noveltyScore,
  };
}

function estimateReachability(finding: ScanFinding): number {
  let score = 0.5;

  const filePath = (finding.filePath ?? "").toLowerCase();
  if (filePath.includes("route") || filePath.includes("controller") || filePath.includes("handler")) {
    score += 0.2;
  }
  if (filePath.includes("api") || filePath.includes("endpoint")) {
    score += 0.2;
  }
  if (filePath.includes("middleware") || filePath.includes("auth")) {
    score += 0.15;
  }
  if (filePath.includes("util") || filePath.includes("helper") || filePath.includes("lib")) {
    score -= 0.1;
  }
  if (filePath.includes("test") || filePath.includes("spec") || filePath.includes("mock")) {
    score -= 0.3;
  }

  if (finding.scanner === "secrets" && finding.confidence > 0.8) {
    score += 0.2;
  }

  return Math.max(0, Math.min(1.0, score));
}

function estimateNovelty(finding: ScanFinding): number {
  const vulnType = finding.vulnerabilityType;
  const highNovelty = [
    "Command Injection",
    "Insecure Deserialization",
    "Server-Side Request Forgery (SSRF)",
    "Exposed Secret",
  ];
  const medNovelty = [
    "SQL Injection",
    "Path Traversal",
    "Hardcoded Secret",
  ];

  if (highNovelty.includes(vulnType)) return 0.8;
  if (medNovelty.includes(vulnType)) return 0.6;
  return 0.4;
}

function estimateBounty(finding: ScanFinding): number {
  const range = BOUNTY_ESTIMATES[finding.severity] ?? { min: 0, max: 100 };
  const multiplier = VULN_TYPE_MULTIPLIERS[finding.vulnerabilityType] ?? 1.0;

  const baseBounty = (range.min + range.max) / 2;
  return baseBounty * multiplier * finding.confidence;
}
