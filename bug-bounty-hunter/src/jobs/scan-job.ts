import { Job, Queue, Worker } from "bullmq";
import IORedis from "ioredis";
import { config } from "../config";
import { createChildLogger } from "../utils/logger";
import { RepoFetcher } from "../core/repo-fetcher";
import { runAllScanners, ScanResult } from "../core/scanners";
import { triageFindings, TriageResult } from "../core/triage";

const log = createChildLogger("scan-job");

export interface ScanJobData {
  repoUrl: string;
  scanners?: ("sast" | "dependency" | "secrets" | "misconfig")[];
  shallow?: boolean;
  confidenceThreshold?: number;
}

export interface ScanJobResult {
  repoUrl: string;
  scanResults: ScanResult[];
  triage: TriageResult;
  duration: number;
}

const QUEUE_NAME = "scan-queue";

let connection: IORedis | null = null;

function getConnection(): IORedis {
  if (!connection) {
    connection = new IORedis(config.redis.url, { maxRetriesPerRequest: null });
  }
  return connection;
}

export function createScanQueue(): Queue<ScanJobData, ScanJobResult> {
  return new Queue(QUEUE_NAME, { connection: getConnection() });
}

export function createScanWorker(
  concurrency = config.scanning.concurrency
): Worker<ScanJobData, ScanJobResult> {
  const worker = new Worker<ScanJobData, ScanJobResult>(
    QUEUE_NAME,
    async (job: Job<ScanJobData>) => {
      return processScanJob(job);
    },
    {
      connection: getConnection(),
      concurrency,
    }
  );

  worker.on("completed", (job) => {
    log.info(
      { jobId: job.id, repoUrl: job.data.repoUrl },
      "Scan job completed"
    );
  });

  worker.on("failed", (job, err) => {
    log.error(
      { jobId: job?.id, err: err.message },
      "Scan job failed"
    );
  });

  return worker;
}

async function processScanJob(
  job: Job<ScanJobData>
): Promise<ScanJobResult> {
  const start = Date.now();
  const { repoUrl, scanners, shallow = true, confidenceThreshold = 0.5 } = job.data;

  log.info({ repoUrl, jobId: job.id }, "Processing scan job");

  await job.updateProgress(10);

  const fetcher = new RepoFetcher();
  const repo = await fetcher.fetch(repoUrl, { shallow });

  await job.updateProgress(30);

  const scanResults = await runAllScanners(repo.localPath, { scanners });
  const allFindings = scanResults.flatMap((r) => r.findings);

  await job.updateProgress(70);

  const triage = await triageFindings(allFindings, { confidenceThreshold });

  await job.updateProgress(100);

  return {
    repoUrl,
    scanResults,
    triage,
    duration: Date.now() - start,
  };
}
