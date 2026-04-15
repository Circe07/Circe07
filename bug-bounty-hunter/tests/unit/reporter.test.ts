import { describe, it, expect } from "vitest";
import { generateReport } from "../../src/core/reporter/generator";
import { ScoredFinding } from "../../src/core/triage/scorer";

function makeScoredFinding(overrides: Partial<ScoredFinding> = {}): ScoredFinding {
  return {
    scanner: "sast",
    vulnerabilityType: "SQL Injection",
    severity: "high",
    cweId: "CWE-89",
    title: "SQL Injection in users.ts",
    description: "Potential SQL injection via string interpolation",
    filePath: "src/routes/users.ts",
    lineNumber: 42,
    codeSnippet: 'db.query(`SELECT * FROM users WHERE id = ${id}`)',
    confidence: 0.8,
    finalScore: 0.75,
    bountyEstimate: 3500,
    severityScore: 0.8,
    confidenceScore: 0.8,
    reachabilityScore: 0.7,
    noveltyScore: 0.6,
    ...overrides,
  };
}

describe("Report Generator", () => {
  it("should generate a generic report with all sections", () => {
    const report = generateReport(makeScoredFinding(), "generic");
    expect(report.title).toContain("CWE-89");
    expect(report.title).toContain("SQL Injection");
    expect(report.severity).toBe("high");
    expect(report.body).toContain("Summary");
    expect(report.body).toContain("Severity");
    expect(report.body).toContain("Steps to Reproduce");
    expect(report.body).toContain("Impact");
    expect(report.body).toContain("Remediation");
    expect(report.body).toContain("References");
    expect(report.platform).toBe("generic");
    expect(report.metadata.bountyEstimate).toBe(3500);
  });

  it("should generate a HackerOne formatted report", () => {
    const report = generateReport(makeScoredFinding(), "hackerone");
    expect(report.body).toContain("Steps To Reproduce");
    expect(report.body).toContain("Impact");
    expect(report.body).toContain("Severity Justification");
    expect(report.body).toContain("Suggested Fix");
    expect(report.platform).toBe("hackerone");
  });

  it("should generate a Bugcrowd formatted report", () => {
    const report = generateReport(makeScoredFinding(), "bugcrowd");
    expect(report.body).toContain("Vulnerability Type");
    expect(report.body).toContain("Proof of Concept");
    expect(report.body).toContain("Steps to Reproduce");
    expect(report.body).toContain("Recommendation");
    expect(report.platform).toBe("bugcrowd");
  });

  it("should include file path and line number", () => {
    const report = generateReport(makeScoredFinding(), "generic");
    expect(report.body).toContain("src/routes/users.ts");
    expect(report.body).toContain("42");
  });

  it("should include code snippet", () => {
    const report = generateReport(makeScoredFinding(), "generic");
    expect(report.body).toContain("SELECT * FROM users");
  });

  it("should handle findings without optional fields", () => {
    const report = generateReport(
      makeScoredFinding({
        cweId: undefined,
        cvssScore: undefined,
        filePath: undefined,
        lineNumber: undefined,
        codeSnippet: undefined,
      }),
      "generic"
    );
    expect(report.title).not.toContain("CWE-");
    expect(report.body).toContain("Summary");
  });
});
