import { searchRepos, getRepoInfo } from "../../utils/github-client";
import { createChildLogger } from "../../utils/logger";
import { githubRateLimiter } from "../../utils/rate-limiter";

const log = createChildLogger("github-search");

export interface GitHubSecurityTarget {
  owner: string;
  repoFullName: string;
  cloneUrl: string;
  language: string | null;
  stars: number;
  securityPolicyUrl?: string;
}

export async function discoverFromGitHub(
  languages?: string[],
  maxResults = 50
): Promise<GitHubSecurityTarget[]> {
  const targets: GitHubSecurityTarget[] = [];

  const queries = buildSearchQueries(languages);

  for (const query of queries) {
    try {
      await githubRateLimiter.acquire();
      const repos = await searchRepos(query, maxResults);

      for (const repo of repos) {
        if (repo.size > 500_000) continue; // skip very large repos

        targets.push({
          owner: repo.owner,
          repoFullName: repo.fullName,
          cloneUrl: repo.cloneUrl,
          language: repo.language,
          stars: repo.stargazersCount,
          securityPolicyUrl: repo.hasSecurityPolicy
            ? `https://github.com/${repo.fullName}/blob/${repo.defaultBranch}/SECURITY.md`
            : undefined,
        });
      }
    } catch (err) {
      log.error({ err, query }, "GitHub search query failed");
    }
  }

  const unique = deduplicateByRepo(targets);
  log.info(
    { count: unique.length },
    "GitHub security targets discovered"
  );
  return unique.slice(0, maxResults);
}

function buildSearchQueries(languages?: string[]): string[] {
  const base = [
    "filename:SECURITY.md stars:>100",
    "filename:security.txt path:.well-known stars:>50",
    "filename:bug-bounty stars:>50",
  ];

  if (languages?.length) {
    const langQueries = languages.flatMap((lang) => [
      `language:${lang} filename:SECURITY.md stars:>50`,
    ]);
    return [...base, ...langQueries];
  }

  return base;
}

function deduplicateByRepo(
  targets: GitHubSecurityTarget[]
): GitHubSecurityTarget[] {
  const seen = new Set<string>();
  return targets.filter((t) => {
    if (seen.has(t.repoFullName)) return false;
    seen.add(t.repoFullName);
    return true;
  });
}
