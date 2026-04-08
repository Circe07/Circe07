import axios from "axios";
import { config } from "../../config";
import { createChildLogger } from "../../utils/logger";

const log = createChildLogger("hackerone");

const HACKERONE_API_BASE = "https://api.hackerone.com/v1";

export interface HackerOneTarget {
  asset_identifier: string;
  asset_type: string;
  eligible_for_bounty: boolean;
  eligible_for_submission: boolean;
}

export interface HackerOneProgram {
  id: string;
  handle: string;
  name: string;
  targets: HackerOneTarget[];
  averageBounty?: number;
  responseTimeDays?: number;
  state: string;
}

export async function discoverFromHackerOne(
  maxResults = 50
): Promise<HackerOneProgram[]> {
  const { apiToken, apiUsername } = config.platforms.hackerone;
  if (!apiToken || !apiUsername) {
    log.warn("HackerOne API credentials not configured, using public directory");
    return discoverFromPublicDirectory(maxResults);
  }

  return discoverFromApi(apiToken, apiUsername, maxResults);
}

async function discoverFromApi(
  token: string,
  username: string,
  maxResults: number
): Promise<HackerOneProgram[]> {
  const programs: HackerOneProgram[] = [];

  try {
    const response = await axios.get(
      `${HACKERONE_API_BASE}/hackers/programs`,
      {
        auth: { username, password: token },
        params: { page: { size: Math.min(maxResults, 100) } },
        timeout: 30_000,
      }
    );

    const data = response.data?.data ?? [];

    for (const program of data) {
      const attrs = program.attributes;
      if (attrs.state !== "public_mode") continue;
      if (!attrs.offers_bounties) continue;

      const targets = extractTargets(program);

      programs.push({
        id: program.id,
        handle: attrs.handle,
        name: attrs.name,
        targets,
        state: attrs.state,
        averageBounty: attrs.average_bounty_lower_amount,
        responseTimeDays: attrs.first_response_time_business_days,
      });
    }

    log.info(
      { count: programs.length },
      "Discovered programs from HackerOne API"
    );
  } catch (err) {
    log.error({ err }, "Failed to fetch from HackerOne API");
  }

  return programs;
}

function extractTargets(program: any): HackerOneTarget[] {
  const relationships = program.relationships?.structured_scopes?.data ?? [];
  return relationships.map((scope: any) => ({
    asset_identifier: scope.attributes.asset_identifier,
    asset_type: scope.attributes.asset_type,
    eligible_for_bounty: scope.attributes.eligible_for_bounty,
    eligible_for_submission: scope.attributes.eligible_for_submission,
  }));
}

async function discoverFromPublicDirectory(
  maxResults: number
): Promise<HackerOneProgram[]> {
  const programs: HackerOneProgram[] = [];

  try {
    const response = await axios.get(
      "https://raw.githubusercontent.com/Hacker0x01/public-programs/main/programs.json",
      { timeout: 15_000 }
    );

    const data = Array.isArray(response.data) ? response.data : [];

    for (const entry of data.slice(0, maxResults)) {
      programs.push({
        id: entry.id ?? entry.handle,
        handle: entry.handle,
        name: entry.name ?? entry.handle,
        targets: [],
        state: "public_mode",
      });
    }

    log.info(
      { count: programs.length },
      "Discovered programs from public directory"
    );
  } catch (err) {
    log.error({ err }, "Failed to fetch public HackerOne programs");
  }

  return programs;
}
