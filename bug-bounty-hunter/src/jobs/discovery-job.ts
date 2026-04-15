import { Job, Queue, Worker } from "bullmq";
import IORedis from "ioredis";
import { config } from "../config";
import { createChildLogger } from "../utils/logger";
import { discoverTargets, DiscoveredTarget } from "../core/target-discovery";

const log = createChildLogger("discovery-job");

export interface DiscoveryJobData {
  platforms?: string[];
  maxResults?: number;
  languages?: string[];
  minBounty?: number;
}

export interface DiscoveryJobResult {
  targets: DiscoveredTarget[];
  duration: number;
}

const QUEUE_NAME = "discovery-queue";

let connection: IORedis | null = null;

function getConnection(): IORedis {
  if (!connection) {
    connection = new IORedis(config.redis.url, { maxRetriesPerRequest: null });
  }
  return connection;
}

export function createDiscoveryQueue(): Queue<DiscoveryJobData, DiscoveryJobResult> {
  return new Queue(QUEUE_NAME, { connection: getConnection() });
}

export function createDiscoveryWorker(): Worker<DiscoveryJobData, DiscoveryJobResult> {
  const worker = new Worker<DiscoveryJobData, DiscoveryJobResult>(
    QUEUE_NAME,
    async (job: Job<DiscoveryJobData>) => {
      return processDiscoveryJob(job);
    },
    {
      connection: getConnection(),
      concurrency: 1,
    }
  );

  worker.on("completed", (job) => {
    log.info(
      { jobId: job.id, targetCount: job.returnvalue?.targets.length },
      "Discovery job completed"
    );
  });

  worker.on("failed", (job, err) => {
    log.error(
      { jobId: job?.id, err: err.message },
      "Discovery job failed"
    );
  });

  return worker;
}

async function processDiscoveryJob(
  job: Job<DiscoveryJobData>
): Promise<DiscoveryJobResult> {
  const start = Date.now();
  const {
    platforms = ["hackerone", "bugcrowd", "github"],
    maxResults = 50,
    languages,
    minBounty,
  } = job.data;

  log.info({ platforms, jobId: job.id }, "Processing discovery job");

  await job.updateProgress(10);

  const targets = await discoverTargets({
    platforms: platforms as any[],
    maxResults,
    languages,
    minBounty,
  });

  await job.updateProgress(100);

  return {
    targets,
    duration: Date.now() - start,
  };
}
