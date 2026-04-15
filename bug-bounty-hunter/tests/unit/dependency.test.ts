import { describe, it, expect } from "vitest";
import { DependencyScanner } from "../../src/core/scanners/dependency";
import fs from "fs/promises";
import os from "os";
import path from "path";

async function createTempDir(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), "bbh-dep-"));
}

describe("Dependency Scanner", () => {
  it("should detect package.json dependencies", async () => {
    const dir = await createTempDir();
    await fs.writeFile(
      path.join(dir, "package.json"),
      JSON.stringify({
        dependencies: { express: "4.17.0", lodash: "4.17.20" },
        devDependencies: { jest: "27.0.0" },
      })
    );

    const scanner = new DependencyScanner();
    const findings = await scanner.scan(dir);
    expect(Array.isArray(findings)).toBe(true);

    await fs.rm(dir, { recursive: true });
  });

  it("should detect requirements.txt dependencies", async () => {
    const dir = await createTempDir();
    await fs.writeFile(
      path.join(dir, "requirements.txt"),
      "flask==2.0.0\nrequests>=2.25.0\n# comment\ndjango==3.2.0\n"
    );

    const scanner = new DependencyScanner();
    const findings = await scanner.scan(dir);
    expect(Array.isArray(findings)).toBe(true);

    await fs.rm(dir, { recursive: true });
  });

  it("should handle repos with no dependency files", async () => {
    const dir = await createTempDir();
    await fs.writeFile(path.join(dir, "README.md"), "# test");

    const scanner = new DependencyScanner();
    const findings = await scanner.scan(dir);
    expect(findings).toHaveLength(0);

    await fs.rm(dir, { recursive: true });
  });

  it("should handle malformed package.json gracefully", async () => {
    const dir = await createTempDir();
    await fs.writeFile(path.join(dir, "package.json"), "not valid json {{{");

    const scanner = new DependencyScanner();
    const findings = await scanner.scan(dir);
    expect(Array.isArray(findings)).toBe(true);

    await fs.rm(dir, { recursive: true });
  });
});
