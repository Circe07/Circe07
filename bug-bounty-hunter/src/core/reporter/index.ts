import { createChildLogger } from "../../utils/logger";
import { ScoredFinding } from "../triage/scorer";
import { generateReport, ReportOutput } from "./generator";
import { submitReport, SubmissionResult } from "./submitter";

const log = createChildLogger("reporter");

export interface ReporterOptions {
  platform?: "hackerone" | "bugcrowd" | "intigriti" | "generic";
  autoSubmit?: boolean;
  programSlug?: string;
}

export interface ReportResult {
  report: ReportOutput;
  submission?: SubmissionResult;
}

export async function createReport(
  finding: ScoredFinding,
  options: ReporterOptions = {}
): Promise<ReportResult> {
  const platform = options.platform ?? "generic";

  log.info(
    { findingTitle: finding.title, platform },
    "Generating report"
  );

  const report = generateReport(finding, platform);

  let submission: SubmissionResult | undefined;

  if (options.autoSubmit && options.programSlug) {
    log.info(
      { platform, programSlug: options.programSlug },
      "Auto-submitting report"
    );

    submission = await submitReport(report, {
      platform,
      programSlug: options.programSlug,
    });
  }

  return { report, submission };
}

export async function createReports(
  findings: ScoredFinding[],
  options: ReporterOptions = {}
): Promise<ReportResult[]> {
  const results: ReportResult[] = [];

  for (const finding of findings) {
    try {
      const result = await createReport(finding, options);
      results.push(result);
    } catch (err) {
      log.error(
        { err, findingTitle: finding.title },
        "Failed to create report"
      );
    }
  }

  log.info(
    { total: results.length },
    "Report generation complete"
  );
  return results;
}
