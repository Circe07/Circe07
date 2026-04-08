import { z } from "zod";
import dotenv from "dotenv";
import path from "path";

dotenv.config();

const configSchema = z.object({
  github: z.object({
    token: z.string().min(1),
    apiRateLimit: z.number().default(5000),
  }),
  database: z.object({
    url: z.string().url(),
  }),
  redis: z.object({
    url: z.string().default("redis://localhost:6379"),
  }),
  platforms: z.object({
    hackerone: z.object({
      apiToken: z.string().optional(),
      apiUsername: z.string().optional(),
    }),
    bugcrowd: z.object({
      apiToken: z.string().optional(),
    }),
    intigriti: z.object({
      apiToken: z.string().optional(),
    }),
  }),
  openai: z.object({
    apiKey: z.string().optional(),
  }),
  scanning: z.object({
    concurrency: z.number().default(3),
    repoCacheDir: z.string().default("./data/repos"),
    maxRepoSizeMb: z.number().default(500),
    timeoutMs: z.number().default(300_000),
  }),
  logging: z.object({
    level: z.string().default("info"),
  }),
  nodeEnv: z.string().default("development"),
});

export type Config = z.infer<typeof configSchema>;

function loadConfig(): Config {
  return configSchema.parse({
    github: {
      token: process.env.GITHUB_TOKEN ?? "",
      apiRateLimit: Number(process.env.GITHUB_API_RATE_LIMIT) || 5000,
    },
    database: {
      url:
        process.env.DATABASE_URL ??
        "postgresql://bounty:bounty@localhost:5432/bugbountyhunter",
    },
    redis: {
      url: process.env.REDIS_URL ?? "redis://localhost:6379",
    },
    platforms: {
      hackerone: {
        apiToken: process.env.HACKERONE_API_TOKEN || undefined,
        apiUsername: process.env.HACKERONE_API_USERNAME || undefined,
      },
      bugcrowd: {
        apiToken: process.env.BUGCROWD_API_TOKEN || undefined,
      },
      intigriti: {
        apiToken: process.env.INTIGRITI_API_TOKEN || undefined,
      },
    },
    openai: {
      apiKey: process.env.OPENAI_API_KEY || undefined,
    },
    scanning: {
      concurrency: Number(process.env.SCAN_CONCURRENCY) || 3,
      repoCacheDir:
        process.env.REPO_CACHE_DIR ??
        path.resolve(process.cwd(), "data", "repos"),
      maxRepoSizeMb: Number(process.env.MAX_REPO_SIZE_MB) || 500,
      timeoutMs: Number(process.env.SCAN_TIMEOUT_MS) || 300_000,
    },
    logging: {
      level: process.env.LOG_LEVEL ?? "info",
    },
    nodeEnv: process.env.NODE_ENV ?? "development",
  });
}

export const config = loadConfig();
