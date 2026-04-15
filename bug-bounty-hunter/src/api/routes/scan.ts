import { FastifyInstance } from "fastify";
import { RepoFetcher } from "../../core/repo-fetcher";
import { runAllScanners } from "../../core/scanners";
import { triageFindings } from "../../core/triage";
import { createChildLogger } from "../../utils/logger";

const log = createChildLogger("scan-routes");

interface ScanRequestBody {
  repoUrl: string;
  scanners?: string[];
  shallow?: boolean;
  confidenceThreshold?: number;
}

export function registerScanRoutes(server: FastifyInstance): void {
  server.post<{ Body: ScanRequestBody }>("/api/scan", async (request, reply) => {
    const {
      repoUrl,
      scanners,
      shallow = true,
      confidenceThreshold = 0.5,
    } = request.body;

    if (!repoUrl) {
      return reply.status(400).send({ error: "repoUrl is required" });
    }

    try {
      const start = Date.now();

      const fetcher = new RepoFetcher();
      const repo = await fetcher.fetch(repoUrl, { shallow });

      const scanResults = await runAllScanners(repo.localPath, {
        scanners: scanners as any,
      });
      const allFindings = scanResults.flatMap((r) => r.findings);

      const triage = await triageFindings(allFindings, { confidenceThreshold });

      return {
        repoUrl,
        duration: Date.now() - start,
        stats: triage.stats,
        confirmed: triage.confirmed.slice(0, 50),
        scanSummary: scanResults.map((r) => ({
          scanner: r.scanner,
          findings: r.findings.length,
          duration: r.duration,
          error: r.error,
        })),
      };
    } catch (err: any) {
      log.error({ err, repoUrl }, "Scan API request failed");
      return reply.status(500).send({ error: err.message });
    }
  });

  server.get("/api/scanners", async () => ({
    available: ["sast", "dependency", "secrets", "misconfig"],
  }));
}
