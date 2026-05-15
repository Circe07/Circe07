import path from "path";
import fs from "fs/promises";
import { config } from "../../config";
import { createChildLogger } from "../../utils/logger";
import { GitClient, CloneOptions } from "./git-client";

const log = createChildLogger("repo-fetcher");

export interface FetchedRepo {
  localPath: string;
  repoUrl: string;
  branch: string;
  commitHash: string;
  language: string | null;
  sizeBytes: number;
}

export interface FetchOptions {
  shallow?: boolean;
  branch?: string;
  maxSizeMb?: number;
}

export class RepoFetcher {
  private cacheDir: string;
  private gitClient: GitClient;

  constructor() {
    this.cacheDir = config.scanning.repoCacheDir;
    this.gitClient = new GitClient();
  }

  async fetch(repoUrl: string, options: FetchOptions = {}): Promise<FetchedRepo> {
    const repoId = this.repoUrlToId(repoUrl);
    const localPath = path.join(this.cacheDir, repoId);

    await fs.mkdir(this.cacheDir, { recursive: true });

    const exists = await this.pathExists(localPath);

    if (exists) {
      log.info({ repoUrl, localPath }, "Repo found in cache, pulling latest");
      await this.gitClient.pull(localPath);
    } else {
      log.info({ repoUrl, localPath }, "Cloning repository");
      const cloneOpts: CloneOptions = {
        url: repoUrl,
        targetDir: localPath,
        shallow: options.shallow ?? true,
        branch: options.branch,
      };
      await this.gitClient.clone(cloneOpts);
    }

    const commitHash = await this.gitClient.getHeadCommit(localPath);
    const branch = await this.gitClient.getCurrentBranch(localPath);
    const sizeBytes = await this.getDirectorySize(localPath);

    const maxBytes = (options.maxSizeMb ?? config.scanning.maxRepoSizeMb) * 1024 * 1024;
    if (sizeBytes > maxBytes) {
      await fs.rm(localPath, { recursive: true, force: true });
      throw new Error(
        `Repository ${repoUrl} exceeds max size (${Math.round(sizeBytes / 1024 / 1024)}MB > ${options.maxSizeMb ?? config.scanning.maxRepoSizeMb}MB)`
      );
    }

    return {
      localPath,
      repoUrl,
      branch,
      commitHash,
      language: null, // Detected later by scanner
      sizeBytes,
    };
  }

  async cleanup(localPath: string): Promise<void> {
    try {
      await fs.rm(localPath, { recursive: true, force: true });
      log.info({ localPath }, "Repository cleaned up");
    } catch (err) {
      log.error({ err, localPath }, "Failed to cleanup repository");
    }
  }

  async cleanupOldRepos(maxAgeDays = 7): Promise<number> {
    let cleaned = 0;
    try {
      const entries = await fs.readdir(this.cacheDir, {
        withFileTypes: true,
      });

      const maxAgeMs = maxAgeDays * 24 * 60 * 60 * 1000;
      const now = Date.now();

      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        const entryPath = path.join(this.cacheDir, entry.name);
        const stat = await fs.stat(entryPath);
        if (now - stat.mtimeMs > maxAgeMs) {
          await fs.rm(entryPath, { recursive: true, force: true });
          cleaned++;
        }
      }

      log.info({ cleaned }, "Old repositories cleaned up");
    } catch (err) {
      log.error({ err }, "Failed to cleanup old repos");
    }
    return cleaned;
  }

  private repoUrlToId(url: string): string {
    return url
      .replace(/https?:\/\//, "")
      .replace(/\.git$/, "")
      .replace(/\//g, "_");
  }

  private async pathExists(p: string): Promise<boolean> {
    try {
      await fs.access(p);
      return true;
    } catch {
      return false;
    }
  }

  private async getDirectorySize(dir: string): Promise<number> {
    let totalSize = 0;
    const entries = await fs.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.name === ".git") continue;
      if (entry.isDirectory()) {
        totalSize += await this.getDirectorySize(fullPath);
      } else {
        const stat = await fs.stat(fullPath);
        totalSize += stat.size;
      }
    }
    return totalSize;
  }
}
