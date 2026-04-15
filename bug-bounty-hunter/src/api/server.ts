import Fastify, { FastifyInstance } from "fastify";
import { createChildLogger } from "../utils/logger";
import { registerScanRoutes } from "./routes/scan";
import { registerDiscoveryRoutes } from "./routes/discovery";
import { registerHealthRoutes } from "./routes/health";

const log = createChildLogger("api-server");

export async function createServer(): Promise<FastifyInstance> {
  const server = Fastify({
    logger: false,
  });

  server.addHook("onRequest", (request, _reply, done) => {
    log.info({ method: request.method, url: request.url }, "Incoming request");
    done();
  });

  registerHealthRoutes(server);
  registerScanRoutes(server);
  registerDiscoveryRoutes(server);

  return server;
}

export async function startServer(port = 3000, host = "0.0.0.0"): Promise<FastifyInstance> {
  const server = await createServer();

  await server.listen({ port, host });
  log.info({ port, host }, "API server started");

  return server;
}
