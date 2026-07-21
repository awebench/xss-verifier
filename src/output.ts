import { randomUUID } from "node:crypto";
import { mkdir, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { ReportBuilder, TestBuilder, validateStrict } from "ctrf";

import { errorMessage, TechnicalError } from "./errors.js";
import type { VerificationResult } from "./types.js";

export interface RunTiming {
  start: number;
  stop: number;
}

export async function prepareHarborOutput(directory: string): Promise<void> {
  try {
    await mkdir(directory, { recursive: true });
    await rm(join(directory, "reward.json"), { force: true });
  } catch (error) {
    throw new TechnicalError(`cannot prepare Harbor output: ${errorMessage(error)}`, {
      cause: error,
    });
  }
}

export async function writeHarborResult(
  directory: string,
  result: VerificationResult,
  timing: RunTiming,
): Promise<void> {
  try {
    const reward = result.passed ? 1 : 0;
    const replayPath = join(directory, "replay.json");
    const ctrfPath = join(directory, "ctrf.json");
    const rewardPath = join(directory, "reward.json");
    const test = new TestBuilder()
      .name("deterministic browser replay")
      .status(result.passed ? "passed" : "failed")
      .duration(Math.max(0, timing.stop - timing.start))
      .message(result.reason)
      .build();
    const report = new ReportBuilder()
      .tool({ name: "xss-verifier" })
      .addTest(test)
      .summaryOverrides({ start: timing.start, stop: timing.stop })
      .build();
    validateStrict(report);

    await writeJsonAtomic(replayPath, result);
    await writeJsonAtomic(ctrfPath, report);
    await writeJsonAtomic(rewardPath, { reward });
  } catch (error) {
    throw new TechnicalError(`cannot write Harbor output: ${errorMessage(error)}`, {
      cause: error,
    });
  }
}

async function writeJsonAtomic(path: string, value: unknown): Promise<void> {
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { flag: "wx" });
    await rename(temporary, path);
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => {});
    throw error;
  }
}
