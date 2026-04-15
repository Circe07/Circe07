import { describe, it, expect } from "vitest";
import { MisconfigScanner } from "../../src/core/scanners/misconfig";
import fs from "fs/promises";
import os from "os";
import path from "path";

async function createTempDir(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), "bbh-misconfig-"));
}

describe("Misconfiguration Scanner", () => {
  it("should detect Dockerfile running as root", async () => {
    const dir = await createTempDir();
    const filePath = path.join(dir, "Dockerfile");
    await fs.writeFile(
      filePath,
      `FROM node:18
WORKDIR /app
COPY . .
RUN npm install
CMD ["node", "server.js"]
`
    );

    const scanner = new MisconfigScanner();
    const findings = await scanner.scan(dir);
    const rootFindings = findings.filter((f) =>
      f.title.includes("Root")
    );
    expect(rootFindings.length).toBeGreaterThan(0);

    await fs.rm(dir, { recursive: true });
  });

  it("should detect secrets in Docker ENV", async () => {
    const dir = await createTempDir();
    const filePath = path.join(dir, "Dockerfile");
    await fs.writeFile(
      filePath,
      `FROM node:18
ENV DATABASE_PASSWORD=supersecret
ENV API_KEY=abc123
WORKDIR /app
`
    );

    const scanner = new MisconfigScanner();
    const findings = await scanner.scan(dir);
    const secretFindings = findings.filter((f) =>
      f.title.includes("Secret")
    );
    expect(secretFindings.length).toBeGreaterThan(0);

    await fs.rm(dir, { recursive: true });
  });

  it("should detect GitHub Actions injection", async () => {
    const dir = await createTempDir();
    const workflowDir = path.join(dir, ".github", "workflows");
    await fs.mkdir(workflowDir, { recursive: true });
    const workflowContent = [
      "name: CI",
      "on:",
      "  issue_comment:",
      "    types: [created]",
      "jobs:",
      "  test:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - run: echo \"${{ github.event.comment.body }}\"",
    ].join("\n");
    await fs.writeFile(path.join(workflowDir, "ci.yml"), workflowContent);

    const scanner = new MisconfigScanner();
    const findings = await scanner.scan(dir);
    const ghaFindings = findings.filter((f) =>
      f.title.includes("GitHub Actions")
    );
    expect(ghaFindings.length).toBeGreaterThan(0);

    await fs.rm(dir, { recursive: true });
  });

  it("should pass for secure Dockerfile", async () => {
    const dir = await createTempDir();
    const filePath = path.join(dir, "Dockerfile");
    await fs.writeFile(
      filePath,
      `FROM node:18-alpine
WORKDIR /app
COPY . .
RUN npm ci --only=production
USER node
CMD ["node", "server.js"]
`
    );

    const scanner = new MisconfigScanner();
    const findings = await scanner.scan(dir);
    const rootFindings = findings.filter((f) =>
      f.title.includes("Root")
    );
    expect(rootFindings.length).toBe(0);

    await fs.rm(dir, { recursive: true });
  });
});
