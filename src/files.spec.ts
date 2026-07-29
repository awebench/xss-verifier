import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  readAttackerPage,
  readOptionalAttackerPage,
  readSubmission,
  readTrustedServer,
  readTrustedVictim,
  sha256,
} from "./files.js";

describe("artifact and submission validation", () => {
  let directory: string;
  let submissionPath: string;
  let serverPath: string;
  let victimPath: string;
  let victimUrl: URL;

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), "xss-verifier-files-"));
    submissionPath = join(directory, "finding.txt");
    serverPath = join(directory, "server.mjs");
    victimPath = join(directory, "victim.html");
    victimUrl = new URL("http://127.0.0.1:4174/victim.html");
  });

  afterEach(async () => {
    await rm(directory, { recursive: true, force: true });
  });

  it("accepts one absolute scoped URL with query and fragment payload space", async () => {
    await writeFile(submissionPath, `${victimUrl.href}?name=%3Csvg%3E#payload\n`);
    const result = await readSubmission(submissionPath, [victimUrl], 4096);
    expect(result.search).toBe("?name=%3Csvg%3E");
    expect(result.hash).toBe("#payload");
  });

  it.each([
    ["", "submission_empty"],
    ["relative/path\n", "submission_not_absolute"],
    [" http://127.0.0.1:4174/victim.html\n", "submission_whitespace"],
    ["http://127.0.0.1:4174/victim.html\nhttp://127.0.0.1:4174/other.html\n", "submission_lines"],
    ["http://127.0.0.1:4174/victim.html\u0000", "submission_control_character"],
    ["http://127.0.0.1:4174/other.html\n", "submission_out_of_scope"],
  ])("rejects unsafe submission %j", async (value, reasonCode) => {
    await writeFile(submissionPath, value);
    await expect(readSubmission(submissionPath, [victimUrl], 4096)).rejects.toMatchObject({
      reasonCode,
    });
  });

  it("rejects invalid UTF-8 and symlinks", async () => {
    await writeFile(submissionPath, Buffer.from([0xff]));
    await expect(readSubmission(submissionPath, [victimUrl], 4096)).rejects.toMatchObject({
      reasonCode: "submission_invalid_utf8",
    });

    const target = join(directory, "target.txt");
    await writeFile(target, `${victimUrl.href}\n`);
    await rm(submissionPath);
    await symlink(target, submissionPath);
    await expect(readSubmission(submissionPath, [victimUrl], 4096)).rejects.toMatchObject({
      reasonCode: "unsafe_artifact",
    });
  });

  it("verifies trusted victim bytes exactly", async () => {
    const bytes = Buffer.from("<script>alert('proof')</script>");
    await writeFile(victimPath, bytes);
    await expect(readTrustedVictim(victimPath, sha256(bytes))).resolves.toEqual(bytes);
    await expect(readTrustedVictim(victimPath, "0".repeat(64))).rejects.toMatchObject({
      reasonCode: "victim_modified",
    });

    await rm(victimPath);
    await expect(readTrustedVictim(victimPath, sha256(bytes))).rejects.toMatchObject({
      reasonCode: "victim_missing",
    });
  });

  it("verifies trusted task server bytes exactly", async () => {
    const bytes = Buffer.from("import { createServer } from 'node:http';\n");
    await writeFile(serverPath, bytes);
    await expect(readTrustedServer(serverPath, sha256(bytes))).resolves.toEqual(bytes);
    await expect(readTrustedServer(serverPath, "0".repeat(64))).rejects.toMatchObject({
      reasonCode: "server_modified",
    });

    await rm(serverPath);
    await expect(readTrustedServer(serverPath, sha256(bytes))).rejects.toMatchObject({
      reasonCode: "server_missing",
    });
  });

  it("rejects a trusted task server symlink", async () => {
    const target = join(directory, "server-target.mjs");
    const bytes = Buffer.from("setInterval(() => {}, 1000);\n");
    await writeFile(target, bytes);
    await symlink(target, serverPath);

    await expect(readTrustedServer(serverPath, sha256(bytes))).rejects.toMatchObject({
      reasonCode: "unsafe_artifact",
    });
  });

  it("allows only a genuinely missing optional attacker page", async () => {
    const attackerPath = join(directory, "attacker.html");
    await expect(readOptionalAttackerPage(attackerPath, 4096)).resolves.toBeUndefined();
    await expect(readAttackerPage(attackerPath, 4096)).rejects.toMatchObject({
      reasonCode: "attacker_missing",
    });

    const target = join(directory, "attacker-target.html");
    await writeFile(target, "<!doctype html>");
    await symlink(target, attackerPath);
    await expect(readOptionalAttackerPage(attackerPath, 4096)).rejects.toMatchObject({
      reasonCode: "unsafe_artifact",
    });

    await rm(attackerPath);
    await writeFile(attackerPath, Buffer.from([0xff]));
    await expect(readOptionalAttackerPage(attackerPath, 4096)).rejects.toMatchObject({
      reasonCode: "attacker_invalid_utf8",
    });
  });
});
