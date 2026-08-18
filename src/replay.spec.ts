import { describe, expect, it } from "vitest";
import type { Browser, ElementHandle } from "puppeteer-core";

import { TechnicalError } from "./errors.js";
import { activateButton, closeBrowser, closeReplayServers, retryDialogTimeout } from "./replay.js";
import { verificationFailure, verificationSuccess } from "./results.js";
import type { RunningServer } from "./server.js";
import type { RunningTaskServer } from "./task-server.js";
import type { VerificationEvidence, VerificationResult } from "./types.js";

describe("replay cleanup", () => {
  it("falls back to DOM activation when a native click fails", async () => {
    let evaluated = false;
    const button = {
      click: () => Promise.reject(new Error("native click failed")),
      evaluate: () => {
        evaluated = true;
        return Promise.resolve(true);
      },
    } as unknown as ElementHandle<HTMLButtonElement>;

    await expect(activateButton(button)).resolves.toBe(true);
    expect(evaluated).toBe(true);
  });

  it("kills a browser whose graceful close exceeds the cleanup deadline", async () => {
    const signals: NodeJS.Signals[] = [];
    const browser = {
      close: () => new Promise<never>(() => {}),
      process: () => ({
        kill(signal: NodeJS.Signals) {
          signals.push(signal);
          return true;
        },
      }),
    } as unknown as Browser;

    await closeBrowser(browser, 1);

    expect(signals).toEqual(["SIGKILL"]);
  });

  it("surfaces a trusted task server close failure after closing static servers", async () => {
    let staticClosed = false;
    const staticServer: RunningServer = {
      async close() {
        staticClosed = true;
      },
    };
    const taskServer: RunningTaskServer = {
      assertRunning() {},
      waitForUnexpectedExit: () => new Promise<never>(() => {}),
      close: () => Promise.reject(new Error("group remains")),
    };

    await expect(closeReplayServers([staticServer], taskServer)).rejects.toMatchObject({
      name: "TechnicalError",
      message: "cannot stop trusted task server: group remains",
    });
    expect(staticClosed).toBe(true);
  });
});

describe("dialog timeout retries", () => {
  it("returns a later success after a dialog timeout", async () => {
    const outcomes = [failure("dialog_timeout"), success()];
    let calls = 0;

    const replay = await retryDialogTimeout(3, async () => outcomes[calls++]!);

    expect(replay).toMatchObject({
      completed: 2,
      result: { passed: true, reasonCode: "proof_observed" },
    });
    expect(calls).toBe(2);
  });

  it("returns the final timeout after exhausting the configured attempts", async () => {
    let calls = 0;

    const replay = await retryDialogTimeout(3, async () => {
      calls += 1;
      return failure("dialog_timeout");
    });

    expect(replay).toMatchObject({
      completed: 3,
      result: { passed: false, reasonCode: "dialog_timeout" },
    });
    expect(calls).toBe(3);
  });

  it.each(["dialog_mismatch", "navigation_failed"] as const)(
    "does not retry %s",
    async (reasonCode) => {
      let calls = 0;

      const replay = await retryDialogTimeout(3, async () => {
        calls += 1;
        return failure(reasonCode);
      });

      expect(replay).toMatchObject({
        completed: 1,
        result: { passed: false, reasonCode },
      });
      expect(calls).toBe(1);
    },
  );

  it("propagates technical failures without retrying", async () => {
    let calls = 0;

    await expect(
      retryDialogTimeout(3, () => {
        calls += 1;
        throw new TechnicalError("browser failed");
      }),
    ).rejects.toThrow("browser failed");
    expect(calls).toBe(1);
  });
});

function success(): VerificationResult {
  return verificationSuccess("proof observed", evidence);
}

function failure(
  reasonCode: "dialog_timeout" | "dialog_mismatch" | "navigation_failed",
): VerificationResult {
  return verificationFailure(reasonCode, "proof failed", evidence);
}

const evidence: VerificationEvidence = {
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
};
