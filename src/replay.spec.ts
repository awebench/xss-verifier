import { describe, expect, it } from "vitest";
import type { Browser, ElementHandle } from "puppeteer-core";

import { activateButton, closeBrowser, closeReplayServers } from "./replay.js";
import type { RunningServer } from "./server.js";
import type { RunningTaskServer } from "./task-server.js";

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
