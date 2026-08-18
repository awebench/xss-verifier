import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { validateStrict } from "ctrf";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { prepareHarborOutput, writeHarborResult } from "./output.js";
import type { VerificationSuccess } from "./types.js";

describe("Harbor output", () => {
  let directory: string;

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), "xss-verifier-output-"));
  });

  afterEach(async () => {
    await rm(directory, { recursive: true, force: true });
  });

  it("invalidates an existing completion marker before a run", async () => {
    const rewardPath = join(directory, "reward.json");
    await writeFile(rewardPath, '{"reward":1}\n');

    await prepareHarborOutput(directory);

    await expect(readFile(rewardPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("publishes a schema-valid CTRF report before the completion marker", async () => {
    await prepareHarborOutput(directory);
    await writeHarborResult(directory, successResult, { start: 1000, stop: 1250 });

    const report: unknown = JSON.parse(await readFile(join(directory, "ctrf.json"), "utf8"));
    expect(() => validateStrict(report)).not.toThrow();
    expect(report).toMatchObject({
      reportFormat: "CTRF",
      results: {
        summary: { tests: 1, passed: 1, failed: 0, start: 1000, stop: 1250 },
        tests: [{ status: "passed", duration: 250 }],
      },
    });
    await expect(readFile(join(directory, "reward.json"), "utf8")).resolves.toBe(
      '{\n  "reward": 1\n}\n',
    );
  });
});

const successResult: VerificationSuccess = {
  schemaVersion: "xss-verifier-result-v1",
  passed: true,
  reasonCode: "proof_observed",
  reason: "proof observed",
  evidence: {
    replayKind: "navigation",
    interaction: { attemptedClicks: 0, successfulClicks: 0, failedClicks: 0 },
    submittedUrl: "http://127.0.0.1:4174/victim.html",
    browserVersion: "Chrome/1",
    dialogs: [],
    matchingDialog: null,
    dialogLimitReached: false,
    finalUrls: [],
    pageLimitReached: false,
    navigationError: null,
  },
};
