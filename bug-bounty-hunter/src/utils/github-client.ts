import { Octokit } from "@octokit/rest";
import { config } from "../config";
import { githubRateLimiter } from "./rate-limiter";
import { createChildLogger } from "./logger";

const log = createChildLogger("github-client");

let octokitInstance: Octokit | null = null;

export function getOctokit(): Octokit {
  if (!octokitInstance) {
    octokitInstance = new Octokit({
      auth: config.github.token,
      throttle: {
        onRateLimit: (retryAfter: number, options: any) => {
          log.warn(
            { retryAfter, route: options?.url },
            "GitHub rate limit hit, retrying"
          );
          return true;
        },
        onSecondaryRateLimit: (_retryAfter: number, options: any) => {
          log.warn(
            { route: options?.url },
            "GitHub secondary rate limit hit"
          );
          return false;
        },
      },
    });
  }
  return octokitInstance;
}

export interface RepoInfo {
  owner: string;
  name: string;
  fullName: string;
  cloneUrl: string;
  defaultBranch: string;
  language: string | null;
  size: number;
  stargazersCount: number;
  topics: string[];
  hasSecurityPolicy: boolean;
}

export async function getRepoInfo(
  owner: string,
  repo: string
): Promise<RepoInfo> {
  await githubRateLimiter.acquire();
  const octokit = getOctokit();

  const { data } = await octokit.repos.get({ owner, repo });

  let hasSecurityPolicy = false;
  try {
    await githubRateLimiter.acquire();
    await octokit.repos.getContent({
      owner,
      repo,
      path: "SECURITY.md",
    });
    hasSecurityPolicy = true;
  } catch {
    // No SECURITY.md found
  }

  return {
    owner: data.owner.login,
    name: data.name,
    fullName: data.full_name,
    cloneUrl: data.clone_url,
    defaultBranch: data.default_branch,
    language: data.language,
    size: data.size,
    stargazersCount: data.stargazers_count,
    topics: data.topics ?? [],
    hasSecurityPolicy,
  };
}

export async function searchRepos(query: string, maxResults = 100) {
  await githubRateLimiter.acquire();
  const octokit = getOctokit();

  const results: RepoInfo[] = [];
  const perPage = Math.min(maxResults, 100);

  const { data } = await octokit.search.repos({
    q: query,
    sort: "stars",
    order: "desc",
    per_page: perPage,
  });

  for (const repo of data.items) {
    results.push({
      owner: repo.owner?.login ?? "",
      name: repo.name,
      fullName: repo.full_name,
      cloneUrl: repo.clone_url,
      defaultBranch: repo.default_branch,
      language: repo.language,
      size: repo.size,
      stargazersCount: repo.stargazers_count,
      topics: repo.topics ?? [],
      hasSecurityPolicy: false,
    });
  }

  log.info(
    { query, count: results.length },
    "GitHub search completed"
  );
  return results;
}
