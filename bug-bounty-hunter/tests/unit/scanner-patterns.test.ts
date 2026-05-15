import { describe, it, expect } from "vitest";
import { SastScanner } from "../../src/core/scanners/sast";
import fs from "fs/promises";
import os from "os";
import path from "path";

async function createTempDir(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), "bbh-test-"));
}

async function writeFile(dir: string, name: string, content: string) {
  const filePath = path.join(dir, name);
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, content);
}

describe("SAST Scanner - Pattern Matching", () => {
  it("should detect SQL injection via template literals", async () => {
    const dir = await createTempDir();
    await writeFile(
      dir,
      "app.js",
      `
const getUser = (id) => {
  return db.query(\`SELECT * FROM users WHERE id = \${id}\`);
};
`
    );

    const scanner = new SastScanner();
    const findings = await scanner.scan(dir);
    const sqli = findings.filter((f) => f.vulnerabilityType === "SQL Injection");
    expect(sqli.length).toBeGreaterThan(0);

    await fs.rm(dir, { recursive: true });
  });

  it("should detect eval() usage", async () => {
    const dir = await createTempDir();
    await writeFile(
      dir,
      "handler.js",
      `
function processInput(input) {
  const result = eval(input);
  return result;
}
`
    );

    const scanner = new SastScanner();
    const findings = await scanner.scan(dir);
    const codeInj = findings.filter(
      (f) => f.vulnerabilityType === "Code Injection"
    );
    expect(codeInj.length).toBeGreaterThan(0);

    await fs.rm(dir, { recursive: true });
  });

  it("should detect hardcoded API keys", async () => {
    const dir = await createTempDir();
    await writeFile(
      dir,
      "config.js",
      `
const config = {
  api_key: "my_secret_key_for_production_use_abcdef",
  database: "localhost"
};
`
    );

    const scanner = new SastScanner();
    const findings = await scanner.scan(dir);
    const secrets = findings.filter(
      (f) => f.vulnerabilityType === "Hardcoded Secret"
    );
    expect(secrets.length).toBeGreaterThan(0);

    await fs.rm(dir, { recursive: true });
  });

  it("should detect innerHTML XSS", async () => {
    const dir = await createTempDir();
    await writeFile(
      dir,
      "view.js",
      `
function render(data) {
  document.getElementById("output").innerHTML = data.userInput;
}
`
    );

    const scanner = new SastScanner();
    const findings = await scanner.scan(dir);
    const xss = findings.filter(
      (f) => f.vulnerabilityType === "Cross-Site Scripting (XSS)"
    );
    expect(xss.length).toBeGreaterThan(0);

    await fs.rm(dir, { recursive: true });
  });

  it("should detect weak crypto usage", async () => {
    const dir = await createTempDir();
    await writeFile(
      dir,
      "crypto.js",
      `
const crypto = require("crypto");
const hash = crypto.createHash("md5").update(password).digest("hex");
`
    );

    const scanner = new SastScanner();
    const findings = await scanner.scan(dir);
    const crypto = findings.filter(
      (f) => f.vulnerabilityType === "Weak Cryptography"
    );
    expect(crypto.length).toBeGreaterThan(0);

    await fs.rm(dir, { recursive: true });
  });

  it("should not flag comments as vulnerabilities", async () => {
    const dir = await createTempDir();
    await writeFile(
      dir,
      "safe.js",
      `
// This is safe: we use parameterized queries not eval
// password: "test123" (just a comment)
const query = db.query("SELECT * FROM users WHERE id = $1", [id]);
`
    );

    const scanner = new SastScanner();
    const findings = await scanner.scan(dir);
    expect(findings.length).toBe(0);

    await fs.rm(dir, { recursive: true });
  });

  it("should detect permissive CORS", async () => {
    const dir = await createTempDir();
    await writeFile(
      dir,
      "server.js",
      `
const express = require("express");
const app = express();
app.use(cors());
`
    );

    const scanner = new SastScanner();
    const findings = await scanner.scan(dir);
    const corsFindings = findings.filter(
      (f) => f.vulnerabilityType === "Misconfiguration"
    );
    expect(corsFindings.length).toBeGreaterThan(0);

    await fs.rm(dir, { recursive: true });
  });
});
