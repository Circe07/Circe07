import { describe, it, expect } from "vitest";
import { SecretScanner } from "../../src/core/scanners/secrets";
import fs from "fs/promises";
import os from "os";
import path from "path";

async function createTempDir(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), "bbh-secret-"));
}

describe("Secret Scanner", () => {
  it("should detect AWS access keys", async () => {
    const dir = await createTempDir();
    await fs.writeFile(
      path.join(dir, "config.js"),
      `const AWS_KEY = "AKIAIOSFODNN7ABCDEFG";\n`
    );

    const scanner = new SecretScanner();
    const findings = await scanner.scan(dir);
    const awsFindings = findings.filter((f) =>
      f.title.includes("AWS")
    );
    expect(awsFindings.length).toBeGreaterThan(0);

    await fs.rm(dir, { recursive: true });
  });

  it("should detect GitHub tokens", async () => {
    const dir = await createTempDir();
    await fs.writeFile(
      path.join(dir, "deploy.sh"),
      `GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12\n`
    );

    const scanner = new SecretScanner();
    const findings = await scanner.scan(dir);
    const ghFindings = findings.filter((f) =>
      f.title.includes("GitHub")
    );
    expect(ghFindings.length).toBeGreaterThan(0);

    await fs.rm(dir, { recursive: true });
  });

  it("should detect private keys", async () => {
    const dir = await createTempDir();
    await fs.writeFile(
      path.join(dir, "server.pem"),
      `-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALRiMLAHudeSA\n-----END RSA PRIVATE KEY-----\n`
    );

    const scanner = new SecretScanner();
    const findings = await scanner.scan(dir);
    const keyFindings = findings.filter((f) =>
      f.title.includes("Private Key")
    );
    expect(keyFindings.length).toBeGreaterThan(0);

    await fs.rm(dir, { recursive: true });
  });

  it("should detect database connection strings", async () => {
    const dir = await createTempDir();
    await fs.writeFile(
      path.join(dir, ".env"),
      `DATABASE_URL=postgres://admin:secretpass@prod-db.internal.io:5432/myapp\n`
    );

    const scanner = new SecretScanner();
    const findings = await scanner.scan(dir);
    const dbFindings = findings.filter((f) =>
      f.title.includes("Database URL")
    );
    expect(dbFindings.length).toBeGreaterThan(0);

    await fs.rm(dir, { recursive: true });
  });

  it("should not flag binary files", async () => {
    const dir = await createTempDir();
    await fs.writeFile(path.join(dir, "image.png"), Buffer.alloc(100));

    const scanner = new SecretScanner();
    const findings = await scanner.scan(dir);
    expect(findings).toHaveLength(0);

    await fs.rm(dir, { recursive: true });
  });

  it("should deduplicate findings from the same location", async () => {
    const dir = await createTempDir();
    await fs.writeFile(
      path.join(dir, "keys.conf"),
      `api_key: "AKIAIOSFODNN7EXAMPLE"\n`
    );

    const scanner = new SecretScanner();
    const findings = await scanner.scan(dir);
    const awsFindings = findings.filter((f) =>
      f.filePath?.includes("keys.conf")
    );
    const uniqueLines = new Set(awsFindings.map((f) => `${f.filePath}:${f.lineNumber}`));
    expect(uniqueLines.size).toBe(awsFindings.length);

    await fs.rm(dir, { recursive: true });
  });
});
