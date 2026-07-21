import { access, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { main, type CliIo } from "./main.js";

describe("CLI application", () => {
  let directory: string;
  let stdout: string[];
  let stderr: string[];
  let io: CliIo;

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), "xss-verifier-main-"));
    stdout = [];
    stderr = [];
    io = {
      stdout: { write: (value) => stdout.push(value) },
      stderr: { write: (value) => stderr.push(value) },
      now: () => 1000,
    };
  });

  afterEach(async () => {
    await rm(directory, { recursive: true, force: true });
  });

  it("prints generated help without requiring verifier configuration", async () => {
    await expect(main(["--help"], {}, io)).resolves.toBe(0);
    expect(stdout.join("")).toContain("--max-evidence-characters");
    expect(stderr).toEqual([]);
  });

  it("removes a stale Harbor marker before validating the verifier configuration", async () => {
    const rewardPath = join(directory, "reward.json");
    await writeFile(rewardPath, '{"reward":1}\n');

    await expect(
      main(
        [],
        {
          XSS_VERIFIER_ADAPTER: "harbor",
          XSS_VERIFIER_OUTPUT_DIRECTORY: directory,
        },
        io,
      ),
    ).resolves.toBe(2);

    await expect(access(rewardPath)).rejects.toMatchObject({ code: "ENOENT" });
    expect(JSON.parse(stderr.join(""))).toMatchObject({
      kind: "configuration",
      reasonCode: "invalid_configuration",
    });
  });

  it("scores a modified victim as a proof failure", async () => {
    const victimPath = join(directory, "victim.html");
    const submissionPath = join(directory, "finding.txt");
    await Promise.all([
      writeFile(victimPath, "<!doctype html><p>Victim</p>"),
      writeFile(submissionPath, "http://127.0.0.1:4174/victim.html\n"),
    ]);

    await expect(
      main(
        [],
        {
          XSS_VERIFIER_ADAPTER: "harbor",
          XSS_VERIFIER_OUTPUT_DIRECTORY: directory,
          XSS_VERIFIER_REPLAY_KIND: "navigation",
          XSS_VERIFIER_SUBMISSION_PATH: submissionPath,
          XSS_VERIFIER_VICTIM_PATH: victimPath,
          XSS_VERIFIER_VICTIM_URL: "http://127.0.0.1:4174/victim.html",
          XSS_VERIFIER_VICTIM_SHA256: "0".repeat(64),
          XSS_VERIFIER_DIALOG_TYPE: "alert",
          XSS_VERIFIER_DIALOG_MESSAGE: "proof",
          XSS_VERIFIER_FRAME_SCOPE: "top",
          XSS_VERIFIER_TIMEOUT_MS: "5000",
          XSS_VERIFIER_BROWSER_PATH: "/unused/chrome",
          XSS_VERIFIER_EXPECTED_BROWSER_VERSION: "1",
        },
        io,
      ),
    ).resolves.toBe(0);

    await expect(readFile(join(directory, "reward.json"), "utf8")).resolves.toBe(
      '{\n  "reward": 0\n}\n',
    );
    expect(JSON.parse(stdout.join(""))).toMatchObject({
      passed: false,
      reasonCode: "victim_modified",
    });
    expect(stderr).toEqual([]);
  });
});
