import { FastifyInstance } from "fastify";
import { discoverTargets } from "../../core/target-discovery";
import { createChildLogger } from "../../utils/logger";

const log = createChildLogger("discovery-routes");

interface DiscoveryRequestBody {
  platforms?: string[];
  maxResults?: number;
  languages?: string[];
  minBounty?: number;
}

export function registerDiscoveryRoutes(server: FastifyInstance): void {
  server.post<{ Body: DiscoveryRequestBody }>("/api/discover", async (request, reply) => {
    const {
      platforms = ["hackerone", "bugcrowd", "github"],
      maxResults = 50,
      languages,
      minBounty,
    } = request.body ?? {};

    try {
      const start = Date.now();
      const targets = await discoverTargets({
        platforms: platforms as any[],
        maxResults,
        languages,
        minBounty,
      });

      return {
        duration: Date.now() - start,
        count: targets.length,
        targets,
      };
    } catch (err: any) {
      log.error({ err }, "Discovery API request failed");
      return reply.status(500).send({ error: err.message });
    }
  });
}
