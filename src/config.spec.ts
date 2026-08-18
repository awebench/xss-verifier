import { describe, expect, it } from "vitest";

import { parseInvocation } from "./config.js";
import { ConfigError } from "./errors.js";
import type { Invocation } from "./types.js";

const baseEnvironment: NodeJS.ProcessEnv = {
  XSS_VERIFIER_SUBMISSION_PATH: "/work/finding.txt",
  XSS_VERIFIER_VICTIM_PATH: "/work/victim.html",
  XSS_VERIFIER_VICTIM_URL: "http://127.0.0.1:4174/victim.html",
  XSS_VERIFIER_VICTIM_SHA256: "a".repeat(64),
  XSS_VERIFIER_ATTACKER_PATH: "/work/attacker.html",
  XSS_VERIFIER_ATTACKER_URL: "http://127.0.0.1:4173/attacker.html",
  XSS_VERIFIER_DIALOG_TYPE: "alert",
  XSS_VERIFIER_DIALOG_MESSAGE: "proof",
  XSS_VERIFIER_FRAME_SCOPE: "top",
  XSS_VERIFIER_TIMEOUT_MS: "5000",
  XSS_VERIFIER_BROWSER_PATH: "/opt/browser",
  XSS_VERIFIER_EXPECTED_BROWSER_VERSION: "1.2.3.4",
};

describe("configuration", () => {
  it("builds a verifier configuration with victim and optional attacker entries", () => {
    const invocation = parseRun([], baseEnvironment);

    expect(invocation).toMatchObject({
      kind: "json",
      config: {
        submissionPath: "/work/finding.txt",
        attacker: { path: "/work/attacker.html" },
        expectation: { dialogType: "alert", message: "proof", frameScope: "top" },
        browser: { sandbox: "enabled" },
        timeoutMs: 5000,
        dialogTimeoutRetries: 0,
      },
    });
    expect(invocation.config.victim.url.href).toBe("http://127.0.0.1:4174/victim.html");
    expect(invocation.config.server).toBeUndefined();
  });

  it("accepts a paired trusted task server path and digest", () => {
    const invocation = parseRun([], {
      ...baseEnvironment,
      XSS_VERIFIER_SERVER_PATH: "/work/server.mjs",
      XSS_VERIFIER_SERVER_SHA256: "b".repeat(64),
    });

    expect(invocation.config.server).toEqual({
      path: "/work/server.mjs",
      sha256: "b".repeat(64),
    });
  });

  it.each([
    [{ XSS_VERIFIER_SERVER_PATH: "/work/server.mjs" }],
    [{ XSS_VERIFIER_SERVER_SHA256: "b".repeat(64) }],
  ])("requires trusted task server fields to be configured together", (addition) => {
    expect(() => parseInvocation([], { ...baseEnvironment, ...addition })).toThrowError(
      /SERVER_PATH and XSS_VERIFIER_SERVER_SHA256 must be configured together/u,
    );
  });

  it("requires attacker-page fields and separate loopback origins", () => {
    expect(() =>
      parseInvocation([], {
        ...baseEnvironment,
        XSS_VERIFIER_ATTACKER_URL: "http://127.0.0.1:4174/attacker.html",
      }),
    ).toThrowError(/distinct origins/u);
  });

  it.each([
    [
      "missing submission path",
      { XSS_VERIFIER_SUBMISSION_PATH: undefined },
      /SUBMISSION_PATH is required/u,
    ],
    ["bad digest", { XSS_VERIFIER_VICTIM_SHA256: "abc" }, /lowercase SHA-256/u],
    [
      "bad server digest",
      {
        XSS_VERIFIER_SERVER_PATH: "/work/server.mjs",
        XSS_VERIFIER_SERVER_SHA256: "abc",
      },
      /lowercase SHA-256/u,
    ],
    ["file victim", { XSS_VERIFIER_VICTIM_URL: "file:///work/victim.html" }, /loopback http/u],
    ["remote victim", { XSS_VERIFIER_VICTIM_URL: "https://example.com/victim" }, /loopback http/u],
    ["bad timeout", { XSS_VERIFIER_TIMEOUT_MS: "0" }, /between 100 and 30000/u],
    [
      "too many dialog timeout retries",
      { XSS_VERIFIER_DIALOG_TIMEOUT_RETRIES: "8" },
      /between 0 and 7/u,
    ],
    ["bad frame scope", { XSS_VERIFIER_FRAME_SCOPE: "parent" }, /Invalid option/u],
    [
      "missing attacker path",
      { XSS_VERIFIER_ATTACKER_PATH: undefined },
      /ATTACKER_PATH is required/u,
    ],
  ])("rejects %s", (_name, replacements, pattern) => {
    const environment = { ...baseEnvironment, ...replacements };
    expect(() => parseInvocation([], environment)).toThrowError(pattern);
  });

  it("lets CLI flags override matching environment variables", () => {
    const invocation = parseRun(
      [
        "--dialog-message",
        "cli-proof",
        "--frame-scope=any",
        "--browser-sandbox",
        "disabled",
        "--dialog-timeout-retries",
        "3",
      ],
      { ...baseEnvironment, XSS_VERIFIER_DIALOG_TIMEOUT_RETRIES: "1" },
    );
    expect(invocation.config).toMatchObject({
      expectation: { message: "cli-proof", frameScope: "any" },
      browser: { sandbox: "disabled" },
      dialogTimeoutRetries: 3,
    });
  });

  it("models Harbor output as a distinct invocation", () => {
    expect(() => parseInvocation(["--adapter", "harbor"], baseEnvironment)).toThrow(ConfigError);
    expect(
      parseRun(["--adapter", "harbor", "--output-directory", "/logs/result"], baseEnvironment),
    ).toMatchObject({ kind: "harbor", outputDirectory: "/logs/result" });
    expect(() =>
      parseInvocation(["--output-directory", "/logs/result"], baseEnvironment),
    ).toThrowError(/requires the Harbor adapter/u);
  });
});

function parseRun(args: readonly string[], environment: NodeJS.ProcessEnv): Invocation {
  const parsed = parseInvocation(args, environment);
  if (parsed.kind !== "run") throw new Error("expected a runnable invocation");
  return parsed.invocation;
}
