import { describe, it, expect } from "vitest";
import { deduplicateFindings, generateFingerprint } from "../../src/core/triage/dedup";
import { scoreFindings } from "../../src/core/triage/scorer";
import { ScanFinding } from "../../src/core/scanners";

function makeFinding(overrides: Partial<ScanFinding> = {}): ScanFinding {
  return {
    scanner: "sast",
    vulnerabilityType: "SQL Injection",
    severity: "high",
    cweId: "CWE-89",
    title: "Test SQL Injection",
    description: "Test description",
    filePath: "src/app.ts",
    lineNumber: 42,
    codeSnippet: 'db.query(`SELECT * FROM users WHERE id = ${userId}`)',
    confidence: 0.8,
    ...overrides,
  };
}

describe("Deduplication", () => {
  it("should remove exact duplicates", () => {
    const findings = [makeFinding(), makeFinding()];
    const result = deduplicateFindings(findings);
    expect(result.unique).toHaveLength(1);
    expect(result.duplicates).toHaveLength(1);
  });

  it("should keep different findings", () => {
    const findings = [
      makeFinding({ filePath: "src/a.ts", lineNumber: 10 }),
      makeFinding({ filePath: "src/b.ts", lineNumber: 20 }),
    ];
    const result = deduplicateFindings(findings);
    expect(result.unique).toHaveLength(2);
    expect(result.duplicates).toHaveLength(0);
  });

  it("should generate consistent fingerprints", () => {
    const finding = makeFinding();
    const fp1 = generateFingerprint(finding);
    const fp2 = generateFingerprint(finding);
    expect(fp1).toBe(fp2);
  });

  it("should generate different fingerprints for different findings", () => {
    const fp1 = generateFingerprint(makeFinding({ filePath: "a.ts" }));
    const fp2 = generateFingerprint(makeFinding({ filePath: "b.ts" }));
    expect(fp1).not.toBe(fp2);
  });
});

describe("Scorer", () => {
  it("should score critical findings higher than low", () => {
    const findings = [
      makeFinding({ severity: "critical", confidence: 0.9 }),
      makeFinding({
        severity: "low",
        confidence: 0.3,
        filePath: "test.ts",
        lineNumber: 1,
      }),
    ];
    const scored = scoreFindings(findings);
    expect(scored[0].finalScore).toBeGreaterThan(scored[1].finalScore);
  });

  it("should estimate bounty based on severity", () => {
    const scored = scoreFindings([
      makeFinding({ severity: "critical", confidence: 0.9 }),
    ]);
    expect(scored[0].bountyEstimate).toBeGreaterThan(0);
  });

  it("should give higher score to findings in route/controller files", () => {
    const routeFinding = makeFinding({
      filePath: "src/routes/users.ts",
      severity: "high",
      confidence: 0.8,
    });
    const utilFinding = makeFinding({
      filePath: "src/utils/helper.ts",
      severity: "high",
      confidence: 0.8,
      codeSnippet: "different snippet",
    });

    const scored = scoreFindings([routeFinding, utilFinding]);
    expect(scored[0].reachabilityScore).toBeGreaterThan(
      scored[1].reachabilityScore
    );
  });

  it("should penalize findings in test files", () => {
    const prodFinding = makeFinding({
      filePath: "src/app.ts",
      confidence: 0.8,
    });
    const testFinding = makeFinding({
      filePath: "tests/app.test.ts",
      confidence: 0.8,
      codeSnippet: "different test snippet",
    });

    const scored = scoreFindings([prodFinding, testFinding]);
    expect(scored[0].reachabilityScore).toBeGreaterThan(
      scored[1].reachabilityScore
    );
  });

  it("should assign all required fields to scored findings", () => {
    const scored = scoreFindings([makeFinding()]);
    const f = scored[0];
    expect(f.finalScore).toBeGreaterThan(0);
    expect(f.bountyEstimate).toBeGreaterThanOrEqual(0);
    expect(f.severityScore).toBeGreaterThan(0);
    expect(f.confidenceScore).toBeDefined();
    expect(f.reachabilityScore).toBeDefined();
    expect(f.noveltyScore).toBeDefined();
  });
});
