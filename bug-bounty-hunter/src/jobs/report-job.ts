import { Job, Queue, Worker } from "bullmq";
import IORedis from "ioredis";
import { config } from "../config";
import { createChildLogger } from "../utils/logger";
import { ScoredFinding } from "../core/triage/scorer";
import { createReports, ReportResult, ReporterOptions } from "../core/reporter";

const log = createChildLogger("report-job");

export interface ReportJobData {
  findings: ScoredFinding[];
  options: ReporterOptions;
}

export interface ReportJobResult {
  reports: ReportResult[];
  duration: number;
}

const QUEUE_NAME = "report-queue";

let connection: IORedis | null = null;

function getConnection(): IORedis {
  if (!connection) {
    connection = new IORedis(config.redis.url, { maxRetriesPerRequest: null });
  }
  return connection;
}

export function createReportQueue(): Queue<ReportJobData, ReportJobResult> {
  return new Queue(QUEUE_NAME, { connection: getConnection() });
}

export function createReportWorker(): Worker<ReportJobData, ReportJobResult> {
  const worker = new Worker<ReportJobData, ReportJobResult>(
    QUEUE_NAME,
    async (job: Job<ReportJobData>) => {
      return processReportJob(job);
    },
    {
      connection: getConnection(),
      concurrency: 2,
    }
  );

  worker.on("completed", (job) => {
    log.info(
      { jobId: job.id, reportCount: job.returnvalue?.reports.length },
      "Report job completed"
    );
  });

  worker.on("failed", (job, err) => {
    log.error(
      { jobId: job?.id, err: err.message },
      "Report job failed"
    );
  });

  return worker;
}

async function processReportJob(
  job: Job<ReportJobData>
): Promise<ReportJobResult> {
  const start = Date.now();
  const { findings, options } = job.data;

  log.info(
    { findingCount: findings.length, platform: options.platform, jobId: job.id },
    "Processing report job"
  );

  await job.updateProgress(10);

  const reports = await createReports(findings, options);

  await job.updateProgress(100);

  return {
    reports,
    duration: Date.now() - start,
  };
}
