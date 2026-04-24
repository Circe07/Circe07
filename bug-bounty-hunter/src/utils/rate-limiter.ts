import { createChildLogger } from "./logger";

const log = createChildLogger("rate-limiter");

interface RateLimiterOptions {
  maxRequests: number;
  windowMs: number;
  name?: string;
}

export class RateLimiter {
  private timestamps: number[] = [];
  private readonly maxRequests: number;
  private readonly windowMs: number;
  private readonly name: string;

  constructor(options: RateLimiterOptions) {
    this.maxRequests = options.maxRequests;
    this.windowMs = options.windowMs;
    this.name = options.name ?? "default";
  }

  async acquire(): Promise<void> {
    const now = Date.now();
    this.timestamps = this.timestamps.filter(
      (t) => now - t < this.windowMs
    );

    if (this.timestamps.length >= this.maxRequests) {
      const oldestInWindow = this.timestamps[0];
      const waitMs = this.windowMs - (now - oldestInWindow) + 100;
      log.debug(
        { limiter: this.name, waitMs },
        "Rate limit reached, waiting"
      );
      await this.sleep(waitMs);
      return this.acquire();
    }

    this.timestamps.push(now);
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

export const githubRateLimiter = new RateLimiter({
  name: "github",
  maxRequests: 30,
  windowMs: 60_000,
});
