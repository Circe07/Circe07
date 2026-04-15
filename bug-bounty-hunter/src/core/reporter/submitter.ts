import axios from "axios";
import { config } from "../../config";
import { createChildLogger } from "../../utils/logger";
import { ReportOutput } from "./generator";

const log = createChildLogger("submitter");

export interface SubmissionOptions {
  platform: string;
  programSlug: string;
  dryRun?: boolean;
}

export interface SubmissionResult {
  success: boolean;
  platform: string;
  reportId?: string;
  url?: string;
  error?: string;
}

export async function submitReport(
  report: ReportOutput,
  options: SubmissionOptions
): Promise<SubmissionResult> {
  if (options.dryRun) {
    log.info(
      { platform: options.platform, title: report.title },
      "Dry run: report not submitted"
    );
    return {
      success: true,
      platform: options.platform,
      reportId: "dry-run",
    };
  }

  switch (options.platform) {
    case "hackerone":
      return submitToHackerOne(report, options.programSlug);
    case "bugcrowd":
      return submitToBugcrowd(report, options.programSlug);
    default:
      log.warn(
        { platform: options.platform },
        "Platform submission not supported, saving report locally"
      );
      return {
        success: false,
        platform: options.platform,
        error: `Submission to ${options.platform} not yet implemented`,
      };
  }
}

async function submitToHackerOne(
  report: ReportOutput,
  programSlug: string
): Promise<SubmissionResult> {
  const { apiToken, apiUsername } = config.platforms.hackerone;

  if (!apiToken || !apiUsername) {
    return {
      success: false,
      platform: "hackerone",
      error: "HackerOne API credentials not configured",
    };
  }

  try {
    const severityRating = mapHackerOneSeverity(report.severity);

    const payload = {
      data: {
        type: "report",
        attributes: {
          team_handle: programSlug,
          title: report.title,
          vulnerability_information: report.body,
          severity_rating: severityRating,
          weakness_id: report.metadata.cweId
            ? getCweWeaknessId(report.metadata.cweId)
            : undefined,
        },
      },
    };

    const response = await axios.post(
      "https://api.hackerone.com/v1/hackers/reports",
      payload,
      {
        auth: { username: apiUsername, password: apiToken },
        headers: { "Content-Type": "application/json" },
        timeout: 30_000,
      }
    );

    const reportId = response.data?.data?.id;
    log.info(
      { reportId, program: programSlug },
      "Report submitted to HackerOne"
    );

    return {
      success: true,
      platform: "hackerone",
      reportId,
      url: `https://hackerone.com/reports/${reportId}`,
    };
  } catch (err: any) {
    const errorMsg = err.response?.data?.errors?.[0]?.detail ?? err.message;
    log.error(
      { err: errorMsg, program: programSlug },
      "HackerOne submission failed"
    );

    return {
      success: false,
      platform: "hackerone",
      error: errorMsg,
    };
  }
}

async function submitToBugcrowd(
  report: ReportOutput,
  programSlug: string
): Promise<SubmissionResult> {
  const { apiToken } = config.platforms.bugcrowd;

  if (!apiToken) {
    return {
      success: false,
      platform: "bugcrowd",
      error: "Bugcrowd API token not configured",
    };
  }

  try {
    const severityValue = mapBugcrowdSeverity(report.severity);

    const payload = {
      data: {
        type: "submission",
        attributes: {
          title: report.title,
          description: report.body,
          severity: severityValue,
          bug_url: "",
        },
        relationships: {
          program: { data: { type: "program", id: programSlug } },
        },
      },
    };

    const response = await axios.post(
      `https://api.bugcrowd.com/submissions`,
      payload,
      {
        headers: {
          Authorization: `Token ${apiToken}`,
          "Content-Type": "application/vnd.bugcrowd+json",
          Accept: "application/vnd.bugcrowd+json",
        },
        timeout: 30_000,
      }
    );

    const reportId = response.data?.data?.id;
    log.info(
      { reportId, program: programSlug },
      "Report submitted to Bugcrowd"
    );

    return {
      success: true,
      platform: "bugcrowd",
      reportId,
      url: `https://bugcrowd.com/submissions/${reportId}`,
    };
  } catch (err: any) {
    const errorMsg = err.response?.data?.errors?.[0]?.detail ?? err.message;
    log.error(
      { err: errorMsg, program: programSlug },
      "Bugcrowd submission failed"
    );

    return {
      success: false,
      platform: "bugcrowd",
      error: errorMsg,
    };
  }
}

function mapHackerOneSeverity(severity: string): string {
  const map: Record<string, string> = {
    critical: "critical",
    high: "high",
    medium: "medium",
    low: "low",
    info: "none",
  };
  return map[severity] ?? "none";
}

function mapBugcrowdSeverity(severity: string): number {
  const map: Record<string, number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
  };
  return map[severity] ?? 1;
}

function getCweWeaknessId(cweId: string): number | undefined {
  const num = parseInt(cweId.replace("CWE-", ""), 10);
  return isNaN(num) ? undefined : num;
}
