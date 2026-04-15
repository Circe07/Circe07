import { FastifyInstance } from "fastify";

export function registerHealthRoutes(server: FastifyInstance): void {
  server.get("/health", async () => ({
    status: "ok",
    timestamp: new Date().toISOString(),
    version: "0.1.0",
  }));

  server.get("/ready", async () => ({
    status: "ready",
    timestamp: new Date().toISOString(),
  }));
}
