import { ScoredFinding } from "../triage/scorer";
import { createChildLogger } from "../../utils/logger";

const log = createChildLogger("report-generator");

export interface ReportOutput {
  title: string;
  severity: string;
  body: string;
  platform: string;
  metadata: {
    cweId?: string;
    cvssScore?: number;
    bountyEstimate: number;
    confidenceScore: number;
  };
}

export function generateReport(
  finding: ScoredFinding,
  platform: string
): ReportOutput {
  const title = formatTitle(finding);
  const body = formatBody(finding, platform);

  return {
    title,
    severity: finding.severity,
    body,
    platform,
    metadata: {
      cweId: finding.cweId,
      cvssScore: finding.cvssScore,
      bountyEstimate: finding.bountyEstimate,
      confidenceScore: finding.confidenceScore,
    },
  };
}

function formatTitle(finding: ScoredFinding): string {
  const cwePrefix = finding.cweId ? `[${finding.cweId}] ` : "";
  const severity = finding.severity.toUpperCase();
  return `${cwePrefix}${finding.vulnerabilityType} - ${severity}`;
}

function formatBody(
  finding: ScoredFinding,
  platform: string
): string {
  switch (platform) {
    case "hackerone":
      return formatHackerOneReport(finding);
    case "bugcrowd":
      return formatBugcrowdReport(finding);
    default:
      return formatGenericReport(finding);
  }
}

function formatGenericReport(finding: ScoredFinding): string {
  const sections: string[] = [];

  sections.push(`## Summary\n\n${finding.description}`);

  sections.push(
    `## Severity\n\n**${finding.severity.toUpperCase()}**${
      finding.cvssScore ? ` (CVSS: ${finding.cvssScore})` : ""
    }${finding.cweId ? `\n\nCWE: ${finding.cweId}` : ""}`
  );

  sections.push(
    `## Vulnerability Details\n\n**Type:** ${finding.vulnerabilityType}\n**Scanner:** ${finding.scanner}`
  );

  if (finding.filePath) {
    let affectedCode = `## Affected Code\n\n**File:** \`${finding.filePath}\``;
    if (finding.lineNumber) {
      affectedCode += `\n**Line:** ${finding.lineNumber}`;
    }
    if (finding.codeSnippet) {
      affectedCode += `\n\n\`\`\`\n${finding.codeSnippet}\n\`\`\``;
    }
    sections.push(affectedCode);
  }

  sections.push(
    `## Steps to Reproduce\n\n1. Navigate to the repository\n2. Open file \`${finding.filePath ?? "N/A"}\`${
      finding.lineNumber ? ` at line ${finding.lineNumber}` : ""
    }\n3. Observe the vulnerable code pattern\n4. [Additional reproduction steps needed based on the specific vulnerability context]`
  );

  sections.push(
    `## Impact\n\n${getImpactDescription(finding)}`
  );

  if (finding.remediation) {
    sections.push(`## Remediation\n\n${finding.remediation}`);
  } else {
    sections.push(
      `## Remediation\n\n${getDefaultRemediation(finding)}`
    );
  }

  sections.push(
    `## References\n\n${getReferences(finding)}`
  );

  return sections.join("\n\n---\n\n");
}

function formatHackerOneReport(finding: ScoredFinding): string {
  return `## Summary
${finding.description}

## Steps To Reproduce
1. Clone or navigate to the repository
2. Open file \`${finding.filePath ?? "N/A"}\`${
    finding.lineNumber ? ` at line ${finding.lineNumber}` : ""
  }
3. Observe the vulnerable code pattern:
${finding.codeSnippet ? `\`\`\`\n${finding.codeSnippet}\n\`\`\`` : "N/A"}
4. [Specific exploitation steps to be determined based on deployment context]

## Impact
${getImpactDescription(finding)}

## Severity Justification
**${finding.severity.toUpperCase()}** - ${finding.vulnerabilityType}
${finding.cweId ? `CWE: ${finding.cweId}` : ""}
${finding.cvssScore ? `CVSS: ${finding.cvssScore}` : ""}

## Supporting Material/References
${getReferences(finding)}

## Suggested Fix
${finding.remediation ?? getDefaultRemediation(finding)}`;
}

function formatBugcrowdReport(finding: ScoredFinding): string {
  return `**Vulnerability Type:** ${finding.vulnerabilityType}
**Severity:** ${finding.severity.toUpperCase()}
${finding.cweId ? `**CWE:** ${finding.cweId}` : ""}

## Description
${finding.description}

## Proof of Concept
**File:** \`${finding.filePath ?? "N/A"}\`
${finding.lineNumber ? `**Line:** ${finding.lineNumber}` : ""}

${finding.codeSnippet ? `\`\`\`\n${finding.codeSnippet}\n\`\`\`` : ""}

## Steps to Reproduce
1. Access the repository source code
2. Navigate to \`${finding.filePath ?? "N/A"}\`
3. Identify the vulnerable pattern at line ${finding.lineNumber ?? "N/A"}
4. [Context-specific exploitation steps required]

## Impact
${getImpactDescription(finding)}

## Recommendation
${finding.remediation ?? getDefaultRemediation(finding)}`;
}

function getImpactDescription(finding: ScoredFinding): string {
  const impacts: Record<string, string> = {
    "SQL Injection":
      "An attacker could execute arbitrary SQL queries, potentially accessing, modifying, or deleting sensitive data in the database. In severe cases, this could lead to full database compromise or remote code execution.",
    "Command Injection":
      "An attacker could execute arbitrary system commands on the server, potentially leading to full system compromise, data exfiltration, or lateral movement.",
    "Cross-Site Scripting (XSS)":
      "An attacker could inject malicious scripts that execute in other users' browsers, potentially stealing session tokens, credentials, or performing actions on behalf of victims.",
    "Server-Side Request Forgery (SSRF)":
      "An attacker could make the server send requests to internal services, potentially accessing cloud metadata, internal APIs, or other restricted resources.",
    "Path Traversal":
      "An attacker could read arbitrary files from the server filesystem, potentially accessing configuration files, credentials, or sensitive data.",
    "Exposed Secret":
      "Exposed credentials could allow unauthorized access to external services, APIs, or infrastructure, potentially leading to data breaches or service abuse.",
    "Hardcoded Secret":
      "Hardcoded credentials in source code can be extracted and used for unauthorized access to services and infrastructure.",
    "Vulnerable Dependency":
      "A vulnerable dependency could be exploited to compromise the application, depending on how the dependency is used.",
    "Insecure Deserialization":
      "An attacker could craft malicious serialized data to achieve remote code execution or other attacks.",
    "Misconfiguration":
      "The misconfiguration could weaken the security posture of the application, potentially enabling further attacks.",
    "Weak Cryptography":
      "Weak cryptographic algorithms could be broken by attackers, compromising the confidentiality or integrity of encrypted data.",
  };

  return (
    impacts[finding.vulnerabilityType] ??
    `This ${finding.severity} severity ${finding.vulnerabilityType} vulnerability could compromise the security of the application and its users.`
  );
}

function getDefaultRemediation(finding: ScoredFinding): string {
  const remediations: Record<string, string> = {
    "SQL Injection":
      "Use parameterized queries or prepared statements instead of string concatenation. Implement an ORM or query builder that handles escaping automatically.",
    "Command Injection":
      "Avoid executing shell commands with user input. If necessary, use allow-lists for permitted values and avoid shell interpretation (e.g., use execFile instead of exec).",
    "Cross-Site Scripting (XSS)":
      "Sanitize and encode all user input before rendering in HTML. Use framework-provided escaping functions and Content Security Policy headers.",
    "Exposed Secret":
      "Immediately rotate the exposed credential. Store secrets in environment variables or a secrets manager, never in source code. Add secret scanning to CI/CD.",
    "Hardcoded Secret":
      "Remove the hardcoded secret and rotate it immediately. Use environment variables or a secrets management solution.",
    "Vulnerable Dependency":
      "Update the affected dependency to the latest patched version. Monitor dependencies with automated tools like Dependabot or Renovate.",
  };

  return (
    remediations[finding.vulnerabilityType] ??
    "Review and fix the identified vulnerability following security best practices for the specific vulnerability type."
  );
}

function getReferences(finding: ScoredFinding): string {
  const refs: string[] = [];

  if (finding.cweId) {
    refs.push(
      `- [${finding.cweId}](https://cwe.mitre.org/data/definitions/${finding.cweId.replace("CWE-", "")}.html)`
    );
  }

  const owaspMap: Record<string, string> = {
    "SQL Injection": "https://owasp.org/Top10/A03_2021-Injection/",
    "Command Injection": "https://owasp.org/Top10/A03_2021-Injection/",
    "Cross-Site Scripting (XSS)": "https://owasp.org/Top10/A03_2021-Injection/",
    "Exposed Secret": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    "Misconfiguration": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    "Vulnerable Dependency": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
  };

  const owaspUrl = owaspMap[finding.vulnerabilityType];
  if (owaspUrl) {
    refs.push(`- [OWASP Top 10](${owaspUrl})`);
  }

  return refs.length > 0
    ? refs.join("\n")
    : "- No additional references";
}
