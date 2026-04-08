import simpleGit, { SimpleGit } from "simple-git";
import { createChildLogger } from "../../utils/logger";

const log = createChildLogger("git-client");

export interface CloneOptions {
  url: string;
  targetDir: string;
  shallow?: boolean;
  branch?: string;
}

export class GitClient {
  private git: SimpleGit;

  constructor() {
    this.git = simpleGit({
      timeout: { block: 120_000 },
    });
  }

  async clone(options: CloneOptions): Promise<void> {
    const cloneArgs: string[] = [];
    if (options.shallow) {
      cloneArgs.push("--depth", "1");
    }
    if (options.branch) {
      cloneArgs.push("--branch", options.branch);
    }

    log.info(
      { url: options.url, shallow: options.shallow },
      "Cloning repository"
    );

    await this.git.clone(options.url, options.targetDir, cloneArgs);
  }

  async cloneFull(url: string, targetDir: string): Promise<void> {
    log.info({ url }, "Full cloning repository (for history analysis)");
    await this.git.clone(url, targetDir);
  }

  async pull(repoPath: string): Promise<void> {
    const localGit = simpleGit(repoPath);
    await localGit.pull();
  }

  async getHeadCommit(repoPath: string): Promise<string> {
    const localGit = simpleGit(repoPath);
    const logResult = await localGit.log({ maxCount: 1 });
    return logResult.latest?.hash ?? "unknown";
  }

  async getCurrentBranch(repoPath: string): Promise<string> {
    const localGit = simpleGit(repoPath);
    const branch = await localGit.branchLocal();
    return branch.current;
  }

  async getCommitHistory(
    repoPath: string,
    maxCount = 100
  ): Promise<string[]> {
    const localGit = simpleGit(repoPath);
    const logResult = await localGit.log({ maxCount });
    return logResult.all.map((c) => c.hash);
  }

  async diffBetween(
    repoPath: string,
    from: string,
    to: string
  ): Promise<string> {
    const localGit = simpleGit(repoPath);
    return localGit.diff([from, to]);
  }
}
