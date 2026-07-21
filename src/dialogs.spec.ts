import { describe, expect, it } from "vitest";

import { dialogMatches } from "./dialogs.js";
import type { DialogEvidence, VerifierConfig } from "./types.js";

const config: VerifierConfig = {
  submissionPath: "/work/finding.txt",
  victim: {
    path: "/work/victim.html",
    url: new URL("http://127.0.0.1:4174/victim.html"),
    sha256: "a".repeat(64),
  },
  attacker: {
    path: "/work/attacker.html",
    url: new URL("http://127.0.0.1:4175/attacker.html"),
  },
  expectation: { dialogType: "alert", message: "proof", frameScope: "top" },
  browser: { executablePath: "/browser", expectedVersion: "1", sandbox: "enabled" },
  timeoutMs: 1000,
  limits: {
    submissionBytes: 4096,
    attackerBytes: 4096,
    dialogs: 10,
    pages: 10,
    characters: 4096,
  },
};

const matchingDialog: DialogEvidence = {
  type: "alert",
  message: "proof",
  url: "http://127.0.0.1:4174/victim.html?payload=x",
  pageUrl: "http://127.0.0.1:4174/victim.html?payload=x",
  frameUrl: "http://127.0.0.1:4174/victim.html?payload=x",
  securityOrigin: "http://127.0.0.1:4174",
  executionOrigin: "http://127.0.0.1:4174",
  topFrame: true,
};

describe("dialog attribution", () => {
  it("accepts only the configured victim dialog", () => {
    expect(dialogMatches(matchingDialog, config)).toBe(true);
  });

  const mismatches: readonly [string, Partial<DialogEvidence>][] = [
    ["attacker origin", { executionOrigin: "http://127.0.0.1:4173" }],
    ["opaque origin", { executionOrigin: "null" }],
    ["missing execution origin", { executionOrigin: null }],
    ["victim iframe", { topFrame: false }],
    ["wrong message", { message: "other" }],
    ["wrong type", { type: "confirm" }],
  ];

  it.each(mismatches)("rejects %s", (_name, changes) => {
    expect(dialogMatches({ ...matchingDialog, ...changes }, config)).toBe(false);
  });

  it("allows a victim iframe only when configured", () => {
    const anyFrameConfig: VerifierConfig = {
      ...config,
      expectation: { ...config.expectation, frameScope: "any" },
    };
    expect(dialogMatches({ ...matchingDialog, topFrame: false }, anyFrameConfig)).toBe(true);
  });

  it.each(["about:blank", "about:srcdoc"])(
    "accepts victim-origin execution in an inherited %s frame",
    (url) => {
      const anyFrameConfig: VerifierConfig = {
        ...config,
        expectation: { ...config.expectation, frameScope: "any" },
      };
      expect(
        dialogMatches(
          {
            ...matchingDialog,
            url,
            frameUrl: url,
            securityOrigin: "://",
            topFrame: false,
          },
          anyFrameConfig,
        ),
      ).toBe(true);
    },
  );

  it("accepts a top-level victim-origin Blob document", () => {
    expect(
      dialogMatches(
        {
          ...matchingDialog,
          url: "blob:http://127.0.0.1:4174/56e67eb1-3db7-46af-9e19-2aa534c41e45",
          frameUrl: "blob:http://127.0.0.1:4174/56e67eb1-3db7-46af-9e19-2aa534c41e45",
        },
        config,
      ),
    ).toBe(true);
  });

  it("uses execution origin rather than document URL or reported security origin", () => {
    expect(
      dialogMatches(
        {
          ...matchingDialog,
          url: "about:blank",
          frameUrl: "about:blank",
          securityOrigin: "http://127.0.0.1:4173",
        },
        config,
      ),
    ).toBe(true);
    expect(
      dialogMatches(
        {
          ...matchingDialog,
          executionOrigin: "http://127.0.0.1:4173",
        },
        config,
      ),
    ).toBe(false);
  });
});
