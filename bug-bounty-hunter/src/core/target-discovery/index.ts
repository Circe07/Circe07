import { createChildLogger } from "../../utils/logger";
import { discoverFromHackerOne, HackerOneProgram } from "./hackerone";
import { discoverFromBugcrowd, BugcrowdProgram } from "./bugcrowd";
import {
  discoverFromGitHub,
  GitHubSecurityTarget,
} from "./github-search";

const log = createChildLogger("target-discovery");

export interface DiscoveredTarget {
  platform: string;
  programSlug: string;
  programName: string;
  programUrl: string;
  githubOrg?: string;
  githubRepos: string[];
  scopeRules: Record<string, unknown>;
  avgBounty?: number;
  responseTimeDays?: number;
}

export interface DiscoveryOptions {
  platforms?: ("hackerone" | "bugcrowd" | "github")[];
  maxResults?: number;
  minBounty?: number;
  languages?: string[];
}

export async function discoverTargets(
  options: DiscoveryOptions = {}
): Promise<DiscoveredTarget[]> {
  const platforms = options.platforms ?? ["hackerone", "bugcrowd", "github"];
  const allTargets: DiscoveredTarget[] = [];

  log.info({ platforms }, "Starting target discovery");

  const tasks: Promise<void>[] = [];

  if (platforms.includes("hackerone")) {
    tasks.push(
      discoverFromHackerOne(options.maxResults)
        .then((programs) => {
          const mapped = programs.map(mapHackerOneTarget);
          allTargets.push(...mapped);
          log.info(
            { count: mapped.length },
            "HackerOne targets discovered"
          );
        })
        .catch((err) =>
          log.error({ err }, "HackerOne discovery failed")
        )
    );
  }

  if (platforms.includes("bugcrowd")) {
    tasks.push(
      discoverFromBugcrowd(options.maxResults)
        .then((programs) => {
          const mapped = programs.map(mapBugcrowdTarget);
          allTargets.push(...mapped);
          log.info(
            { count: mapped.length },
            "Bugcrowd targets discovered"
          );
        })
        .catch((err) =>
          log.error({ err }, "Bugcrowd discovery failed")
        )
    );
  }

  if (platforms.includes("github")) {
    tasks.push(
      discoverFromGitHub(options.languages, options.maxResults)
        .then((targets) => {
          const mapped = targets.map(mapGitHubTarget);
          allTargets.push(...mapped);
          log.info(
            { count: mapped.length },
            "GitHub targets discovered"
          );
        })
        .catch((err) =>
          log.error({ err }, "GitHub discovery failed")
        )
    );
  }

  await Promise.allSettled(tasks);

  const filtered = options.minBounty
    ? allTargets.filter(
        (t) => (t.avgBounty ?? 0) >= (options.minBounty ?? 0)
      )
    : allTargets;

  log.info(
    { total: filtered.length },
    "Target discovery complete"
  );
  return filtered;
}

function mapHackerOneTarget(program: HackerOneProgram): DiscoveredTarget {
  const githubRepos = program.targets
    .filter((t) => t.asset_type === "SOURCE_CODE" && t.asset_identifier.includes("github.com"))
    .map((t) => t.asset_identifier);

  return {
    platform: "hackerone",
    programSlug: program.handle,
    programName: program.name,
    programUrl: `https://hackerone.com/${program.handle}`,
    githubRepos,
    scopeRules: { targets: program.targets },
    avgBounty: program.averageBounty,
    responseTimeDays: program.responseTimeDays,
  };
}

function mapBugcrowdTarget(program: BugcrowdProgram): DiscoveredTarget {
  return {
    platform: "bugcrowd",
    programSlug: program.code,
    programName: program.name,
    programUrl: program.url,
    githubRepos: program.githubRepos,
    scopeRules: { targets: program.targets },
    avgBounty: program.avgReward,
  };
}

function mapGitHubTarget(target: GitHubSecurityTarget): DiscoveredTarget {
  return {
    platform: "github",
    programSlug: target.repoFullName.replace("/", "-"),
    programName: target.repoFullName,
    programUrl: `https://github.com/${target.repoFullName}`,
    githubOrg: target.owner,
    githubRepos: [`https://github.com/${target.repoFullName}`],
    scopeRules: { securityPolicy: target.securityPolicyUrl },
  };
}
