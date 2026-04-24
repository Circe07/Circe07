import { Command } from "commander";
import { createChildLogger } from "./utils/logger";
import { discoverTargets } from "./core/target-discovery";
import { RepoFetcher } from "./core/repo-fetcher";
import { runAllScanners, filterBySeverity, sortByPriority } from "./core/scanners";
import { triageFindings } from "./core/triage";
import { createReports } from "./core/reporter";

const log = createChildLogger("cli");

const program = new Command();

program
  .name("bbhunter")
  .description("Automated Bug Bounty vulnerability discovery system")
  .version("0.1.0");

program
  .command("discover")
  .description("Discover bug bounty programs and targets")
  .option("-p, --platforms <platforms>", "Platforms to search (comma-separated)", "hackerone,bugcrowd,github")
  .option("-m, --max <number>", "Maximum results per platform", "50")
  .option("-l, --languages <languages>", "Filter by languages (comma-separated)")
  .option("--min-bounty <number>", "Minimum average bounty")
  .action(async (opts) => {
    try {
      const platforms = opts.platforms.split(",") as any[];
      const targets = await discoverTargets({
        platforms,
        maxResults: parseInt(opts.max, 10),
        languages: opts.languages?.split(","),
        minBounty: opts.minBounty ? parseFloat(opts.minBounty) : undefined,
      });

      console.log(`\n  Found ${targets.length} targets:\n`);
      for (const target of targets) {
        console.log(`  [${target.platform}] ${target.programName}`);
        console.log(`    URL: ${target.programUrl}`);
        console.log(`    Repos: ${target.githubRepos.length}`);
        if (target.avgBounty) {
          console.log(`    Avg Bounty: $${target.avgBounty}`);
        }
        console.log();
      }
    } catch (err) {
      log.error({ err }, "Discovery failed");
      process.exit(1);
    }
  });

program
  .command("scan")
  .description("Scan a repository for vulnerabilities")
  .requiredOption("-r, --repo <url>", "Repository URL to scan")
  .option("-s, --scanners <scanners>", "Scanners to run (comma-separated)", "sast,dependency,secrets,misconfig")
  .option("--severity <level>", "Minimum severity to report", "low")
  .option("--shallow", "Use shallow clone", true)
  .option("--full-history", "Clone full history for secret scanning")
  .action(async (opts) => {
    try {
      console.log(`\n  Scanning ${opts.repo}...\n`);

      const fetcher = new RepoFetcher();
      const repo = await fetcher.fetch(opts.repo, {
        shallow: !opts.fullHistory,
      });

      console.log(`  Cloned to: ${repo.localPath}`);
      console.log(`  Commit: ${repo.commitHash}`);
      console.log(`  Branch: ${repo.branch}\n`);

      const scanners = opts.scanners.split(",") as any[];
      const results = await runAllScanners(repo.localPath, { scanners });

      const allFindings = results.flatMap((r) => r.findings);
      const filtered = filterBySeverity(allFindings, opts.severity);
      const sorted = sortByPriority(filtered);

      console.log(`\n  Scan Results:`);
      console.log(`  Total findings: ${allFindings.length}`);
      console.log(`  After filtering (>=${opts.severity}): ${filtered.length}\n`);

      for (const result of results) {
        console.log(`  [${result.scanner}] ${result.findings.length} findings (${result.duration}ms)`);
        if (result.error) {
          console.log(`    Error: ${result.error}`);
        }
      }

      if (sorted.length > 0) {
        console.log("\n  Top Findings:\n");
        for (const finding of sorted.slice(0, 20)) {
          const icon =
            finding.severity === "critical" ? "!!" :
            finding.severity === "high" ? "!" :
            finding.severity === "medium" ? "*" : "-";
          console.log(`  [${icon}] ${finding.severity.toUpperCase()} | ${finding.title}`);
          if (finding.filePath) {
            console.log(`      File: ${finding.filePath}:${finding.lineNumber ?? ""}`);
          }
          console.log(`      Confidence: ${(finding.confidence * 100).toFixed(0)}%`);
          console.log();
        }
      }
    } catch (err) {
      log.error({ err }, "Scan failed");
      process.exit(1);
    }
  });

program
  .command("triage")
  .description("Triage scan results and estimate bounties")
  .requiredOption("-r, --repo <url>", "Repository URL to scan and triage")
  .option("--threshold <number>", "Confidence threshold (0-1)", "0.5")
  .option("--scanners <scanners>", "Scanners to run", "sast,dependency,secrets,misconfig")
  .action(async (opts) => {
    try {
      console.log(`\n  Scanning and triaging ${opts.repo}...\n`);

      const fetcher = new RepoFetcher();
      const repo = await fetcher.fetch(opts.repo, { shallow: true });

      const scanners = opts.scanners.split(",") as any[];
      const results = await runAllScanners(repo.localPath, { scanners });
      const allFindings = results.flatMap((r) => r.findings);

      const triage = await triageFindings(allFindings, {
        confidenceThreshold: parseFloat(opts.threshold),
      });

      console.log(`\n  Triage Results:`);
      console.log(`  Total scanned: ${triage.stats.total}`);
      console.log(`  Confirmed: ${triage.stats.confirmed}`);
      console.log(`  Rejected: ${triage.stats.rejected}`);
      console.log(`  Duplicates: ${triage.stats.duplicates}`);
      console.log(`  Avg Confidence: ${(triage.stats.avgConfidence * 100).toFixed(0)}%`);
      console.log(`  Estimated Bounty: $${triage.stats.estimatedTotalBounty}\n`);

      if (triage.confirmed.length > 0) {
        console.log("  Confirmed Findings (by priority):\n");
        for (const finding of triage.confirmed.slice(0, 15)) {
          console.log(`  [Score: ${finding.finalScore.toFixed(2)}] ${finding.title}`);
          console.log(`    Severity: ${finding.severity} | Bounty Est: $${finding.bountyEstimate}`);
          if (finding.filePath) {
            console.log(`    File: ${finding.filePath}:${finding.lineNumber ?? ""}`);
          }
          console.log();
        }
      }
    } catch (err) {
      log.error({ err }, "Triage failed");
      process.exit(1);
    }
  });

program
  .command("report")
  .description("Generate vulnerability reports for submission")
  .requiredOption("-r, --repo <url>", "Repository URL to scan and report")
  .option("-p, --platform <platform>", "Target platform", "generic")
  .option("--threshold <number>", "Confidence threshold", "0.6")
  .option("--max-reports <number>", "Maximum reports to generate", "10")
  .action(async (opts) => {
    try {
      console.log(`\n  Generating reports for ${opts.repo}...\n`);

      const fetcher = new RepoFetcher();
      const repo = await fetcher.fetch(opts.repo, { shallow: true });

      const results = await runAllScanners(repo.localPath);
      const allFindings = results.flatMap((r) => r.findings);

      const triage = await triageFindings(allFindings, {
        confidenceThreshold: parseFloat(opts.threshold),
      });

      const topFindings = triage.confirmed.slice(
        0,
        parseInt(opts.maxReports, 10)
      );

      if (topFindings.length === 0) {
        console.log("  No findings above confidence threshold. Nothing to report.\n");
        return;
      }

      const reports = await createReports(topFindings, {
        platform: opts.platform,
      });

      console.log(`  Generated ${reports.length} reports:\n`);
      for (const { report } of reports) {
        console.log(`  [${report.severity.toUpperCase()}] ${report.title}`);
        console.log(`    Platform: ${report.platform}`);
        console.log(`    Est. Bounty: $${report.metadata.bountyEstimate}`);
        console.log();
      }

      console.log("  Use --platform hackerone|bugcrowd to format for specific platforms.");
      console.log("  Reports are saved as drafts. Review before submitting.\n");
    } catch (err) {
      log.error({ err }, "Report generation failed");
      process.exit(1);
    }
  });

program
  .command("pipeline")
  .description("Run full pipeline: discover -> scan -> triage -> report")
  .option("-p, --platforms <platforms>", "Discovery platforms", "github")
  .option("--max-targets <number>", "Max targets to scan", "5")
  .option("--threshold <number>", "Confidence threshold", "0.6")
  .option("--report-platform <platform>", "Report platform", "generic")
  .action(async (opts) => {
    try {
      console.log("\n  Starting full bug bounty hunting pipeline...\n");

      console.log("  [1/4] Discovering targets...");
      const targets = await discoverTargets({
        platforms: opts.platforms.split(","),
        maxResults: parseInt(opts.maxTargets, 10),
      });
      console.log(`  Found ${targets.length} targets\n`);

      const fetcher = new RepoFetcher();
      let totalFindings = 0;
      let totalBounty = 0;

      for (const target of targets.slice(0, parseInt(opts.maxTargets, 10))) {
        for (const repoUrl of target.githubRepos.slice(0, 3)) {
          try {
            console.log(`  [2/4] Scanning ${repoUrl}...`);
            const repo = await fetcher.fetch(repoUrl, { shallow: true });

            console.log(`  [3/4] Running scanners...`);
            const results = await runAllScanners(repo.localPath);
            const allFindings = results.flatMap((r) => r.findings);

            const triage = await triageFindings(allFindings, {
              confidenceThreshold: parseFloat(opts.threshold),
            });

            totalFindings += triage.stats.confirmed;
            totalBounty += triage.stats.estimatedTotalBounty;

            if (triage.confirmed.length > 0) {
              console.log(`  [4/4] Generating ${triage.confirmed.length} reports...`);
              await createReports(triage.confirmed, {
                platform: opts.reportPlatform,
              });
            }

            console.log(
              `  Completed: ${triage.stats.confirmed} findings, est. $${triage.stats.estimatedTotalBounty}\n`
            );
          } catch (err) {
            log.error({ err, repoUrl }, "Pipeline failed for repo");
          }
        }
      }

      console.log("\n  Pipeline Summary:");
      console.log(`  Total confirmed findings: ${totalFindings}`);
      console.log(`  Estimated total bounty: $${totalBounty}\n`);
    } catch (err) {
      log.error({ err }, "Pipeline failed");
      process.exit(1);
    }
  });

program.parse();
