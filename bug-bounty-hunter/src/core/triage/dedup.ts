import crypto from "crypto";
import { ScanFinding } from "../scanners";
import { createChildLogger } from "../../utils/logger";

const log = createChildLogger("dedup");

export interface DedupResult {
  unique: ScanFinding[];
  duplicates: ScanFinding[];
}

export function deduplicateFindings(findings: ScanFinding[]): DedupResult {
  const fingerprints = new Map<string, ScanFinding>();
  const duplicates: ScanFinding[] = [];

  for (const finding of findings) {
    const fp = generateFingerprint(finding);

    if (fingerprints.has(fp)) {
      duplicates.push(finding);
      log.debug(
        { fingerprint: fp, title: finding.title },
        "Duplicate finding detected"
      );
    } else {
      fingerprints.set(fp, finding);
    }
  }

  return {
    unique: Array.from(fingerprints.values()),
    duplicates,
  };
}

export function generateFingerprint(finding: ScanFinding): string {
  const components = [
    finding.vulnerabilityType,
    finding.filePath ?? "",
    finding.cweId ?? "",
    normalizeCodeSnippet(finding.codeSnippet ?? ""),
  ];

  const raw = components.join("::");
  return crypto.createHash("sha256").update(raw).digest("hex").slice(0, 16);
}

function normalizeCodeSnippet(snippet: string): string {
  return snippet
    .replace(/\s+/g, " ")
    .replace(/['"`]/g, "")
    .trim()
    .slice(0, 200);
}

export function isSimilarFinding(a: ScanFinding, b: ScanFinding): boolean {
  if (a.vulnerabilityType !== b.vulnerabilityType) return false;
  if (a.filePath === b.filePath && a.lineNumber === b.lineNumber) return true;

  if (a.codeSnippet && b.codeSnippet) {
    const similarity = calculateStringSimilarity(
      a.codeSnippet,
      b.codeSnippet
    );
    return similarity > 0.8;
  }

  return false;
}

function calculateStringSimilarity(a: string, b: string): number {
  if (a === b) return 1.0;
  if (a.length === 0 || b.length === 0) return 0.0;

  const maxLen = Math.max(a.length, b.length);
  const distance = levenshteinDistance(
    a.slice(0, 200),
    b.slice(0, 200)
  );
  return 1 - distance / maxLen;
}

function levenshteinDistance(a: string, b: string): number {
  const matrix: number[][] = [];

  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }

  return matrix[b.length][a.length];
}
