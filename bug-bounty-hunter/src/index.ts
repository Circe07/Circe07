import { logger } from "./utils/logger";

logger.info("BugBountyHunter - Automated Security Vulnerability Discovery");
logger.info("Use 'npx tsx src/cli.ts --help' to see available commands");
logger.info("");
logger.info("Available commands:");
logger.info("  discover   - Find bug bounty programs and targets");
logger.info("  scan       - Scan a repository for vulnerabilities");
logger.info("  triage     - Scan, triage, and estimate bounties");
logger.info("  report     - Generate vulnerability reports");
logger.info("  pipeline   - Run the full automated pipeline");
