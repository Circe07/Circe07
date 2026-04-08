import axios from "axios";
import { config } from "../../config";
import { createChildLogger } from "../../utils/logger";

const log = createChildLogger("bugcrowd");

export interface BugcrowdProgram {
  code: string;
  name: string;
  url: string;
  targets: string[];
  githubRepos: string[];
  avgReward?: number;
}

export async function discoverFromBugcrowd(
  maxResults = 50
): Promise<BugcrowdProgram[]> {
  const programs: BugcrowdProgram[] = [];

  try {
    const response = await axios.get(
      "https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/main/chaos-bugbounty-list.json",
      { timeout: 15_000 }
    );

    const data = response.data?.programs ?? [];

    for (const entry of data.slice(0, maxResults)) {
      const githubRepos = (entry.domains ?? [])
        .filter(
          (d: string) =>
            d.includes("github.com") && !d.includes("*.github.com")
        );

      programs.push({
        code: entry.name?.toLowerCase().replace(/\s+/g, "-") ?? "",
        name: entry.name ?? "",
        url: entry.url ?? "",
        targets: entry.domains ?? [],
        githubRepos,
        avgReward: entry.bounty ? parseFloat(entry.bounty) : undefined,
      });
    }

    log.info(
      { count: programs.length },
      "Discovered programs from Bugcrowd/public lists"
    );
  } catch (err) {
    log.error({ err }, "Failed to fetch Bugcrowd programs");
  }

  return programs;
}
