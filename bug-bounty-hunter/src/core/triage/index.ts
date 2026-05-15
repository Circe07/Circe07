import { createChildLogger } from "../../utils/logger";
import { ScanFinding } from "../scanners";
import { deduplicateFindings } from "./dedup";
import { scoreFindings, ScoredFinding } from "./scorer";

const log = createChildLogger("triage");

export interface TriageResult {
  confirmed: ScoredFinding[];
  rejected: ScoredFinding[];
  duplicates: ScanFinding[];
  stats: {
    total: number;
    confirmed: number;
    rejected: number;
    duplicates: number;
    avgConfidence: number;
    estimatedTotalBounty: number;
  };
}

export interface TriageOptions {
  confidenceThreshold?: number;
  deduplication?: boolean;
}

export async function triageFindings(
  findings: ScanFinding[],
  options: TriageOptions = {}
): Promise<TriageResult> {
  const threshold = options.confidenceThreshold ?? 0.5;
  const shouldDedup = options.deduplication ?? true;

  log.info(
    { findingsCount: findings.length, threshold },
    "Starting triage"
  );

  let duplicates: ScanFinding[] = [];
  let uniqueFindings = findings;

  if (shouldDedup) {
    const dedupResult = deduplicateFindings(findings);
    uniqueFindings = dedupResult.unique;
    duplicates = dedupResult.duplicates;
    log.info(
      {
        unique: uniqueFindings.length,
        duplicates: duplicates.length,
      },
      "Deduplication complete"
    );
  }

  const scored = scoreFindings(uniqueFindings);

  const confirmed = scored.filter((f) => f.finalScore >= threshold);
  const rejected = scored.filter((f) => f.finalScore < threshold);

  const avgConfidence =
    confirmed.length > 0
      ? confirmed.reduce((sum, f) => sum + f.finalScore, 0) / confirmed.length
      : 0;

  const estimatedTotalBounty = confirmed.reduce(
    (sum, f) => sum + (f.bountyEstimate ?? 0),
    0
  );

  const result: TriageResult = {
    confirmed: confirmed.sort((a, b) => b.finalScore - a.finalScore),
    rejected,
    duplicates,
    stats: {
      total: findings.length,
      confirmed: confirmed.length,
      rejected: rejected.length,
      duplicates: duplicates.length,
      avgConfidence: Math.round(avgConfidence * 100) / 100,
      estimatedTotalBounty: Math.round(estimatedTotalBounty),
    },
  };

  log.info({ stats: result.stats }, "Triage complete");
  return result;
}
