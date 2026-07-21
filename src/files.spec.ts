import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { readSubmission, readTrustedVictim, sha256 } from "./files.js";

describe("artifact and submission validation", () => {
  let directory: string;
  let submissionPath: string;
  let victimPath: string;
  let victimUrl: URL;

  beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), "xss-verifier-files-"));
    submissionPath = join(directory, "finding.txt");
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
});
