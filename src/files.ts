import { constants, type BigIntStats } from "node:fs";
import { open } from "node:fs/promises";
import { createHash } from "node:crypto";
import { TextDecoder } from "node:util";

import { errorMessage, isNodeError, ProofError, TechnicalError } from "./errors.js";
import type { ProofFailureCode } from "./types.js";
import { sameDocumentBase } from "./urls.js";

type ArtifactIssueKind = "missing" | "unsafe" | "too-large" | "changed";

class ArtifactIssue extends Error {
  constructor(
    readonly kind: ArtifactIssueKind,
    message: string,
  ) {
    super(message);
  }
}

export function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

async function readRegularFile(path: string, maxBytes: number): Promise<Buffer> {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") {
      throw new ArtifactIssue("missing", `${path} does not exist`);
    }
    if (isNodeError(error) && error.code === "ELOOP") {
      throw new ArtifactIssue("unsafe", `${path} must not be a symbolic link`);
    }
    throw new TechnicalError(`cannot open configured path ${path}: ${errorMessage(error)}`, {
      cause: error,
    });
  }

  try {
    const before = await handle.stat({ bigint: true });
    validateMetadata(path, before, maxBytes);
    const bytes = await handle.readFile();
    if (bytes.length > maxBytes) {
      throw new ArtifactIssue("too-large", `${path} exceeds ${maxBytes} bytes`);
    }
    const after = await handle.stat({ bigint: true });
    if (metadataChanged(before, after)) {
      throw new ArtifactIssue("changed", `${path} changed while it was being read`);
    }
    return bytes;
  } catch (error) {
    if (error instanceof ArtifactIssue) throw error;
    throw new TechnicalError(`cannot read configured path ${path}: ${errorMessage(error)}`, {
      cause: error,
    });
  } finally {
    await handle.close().catch(() => {});
  }
}

function validateMetadata(path: string, metadata: BigIntStats, maxBytes: number): void {
  if (!metadata.isFile()) {
    throw new ArtifactIssue("unsafe", `${path} is not a regular file`);
  }
  if (metadata.size > BigInt(maxBytes)) {
    throw new ArtifactIssue("too-large", `${path} exceeds ${maxBytes} bytes`);
  }
}

function metadataChanged(before: BigIntStats, after: BigIntStats): boolean {
  return (
    before.dev !== after.dev ||
    before.ino !== after.ino ||
    before.size !== after.size ||
    before.mtimeNs !== after.mtimeNs ||
    before.ctimeNs !== after.ctimeNs
  );
}

export async function readTrustedVictim(path: string, expectedSha256: string): Promise<Buffer> {
  const bytes = await readArtifactForProof(
    path,
    16 * 1024 * 1024,
    "victim_missing",
    "the trusted victim reproduction is missing",
  );
  if (sha256(bytes) !== expectedSha256) {
    throw new ProofError(
      "victim_modified",
      "the trusted victim reproduction does not match its configured SHA-256",
    );
  }
  return bytes;
}

export async function readAttackerPage(path: string, maxBytes: number): Promise<Buffer> {
  const bytes = await readArtifactForProof(
    path,
    maxBytes,
    "attacker_missing",
    "the attacker page is missing",
  );
  decodeUtf8(bytes, "attacker_invalid_utf8", "the attacker page is not valid UTF-8");
  return bytes;
}

export async function readSubmission(
  path: string,
  allowedBase: URL,
  maxBytes: number,
): Promise<URL> {
  const bytes = await readArtifactForProof(
    path,
    maxBytes,
    "submission_missing",
    "the submitted proof URL is missing",
  );
  if (bytes.length === 0) {
    throw new ProofError("submission_empty", "the submitted proof URL is empty");
  }

  let text = decodeUtf8(
    bytes,
    "submission_invalid_utf8",
    "the submitted proof URL is not valid UTF-8",
  );
  if (text.startsWith("\uFEFF")) {
    throw new ProofError("submission_bom", "the submitted proof URL starts with a byte-order mark");
  }
  if (text.endsWith("\r\n")) {
    text = text.slice(0, -2);
  } else if (text.endsWith("\n")) {
    text = text.slice(0, -1);
  }
  if (text.length === 0 || text.includes("\n") || text.includes("\r")) {
    throw new ProofError(
      "submission_lines",
      "the submitted proof URL must contain exactly one line",
    );
  }
  if (containsControlCharacter(text)) {
    throw new ProofError(
      "submission_control_character",
      "the submitted proof URL contains a control character",
    );
  }
  if (text.trim() !== text) {
    throw new ProofError(
      "submission_whitespace",
      "the submitted proof URL has surrounding whitespace",
    );
  }

  let url: URL;
  try {
    url = new URL(text);
  } catch {
    throw new ProofError("submission_not_absolute", "the submitted proof is not an absolute URL");
  }
  if (url.username || url.password) {
    throw new ProofError("submission_credentials", "the submitted proof URL contains credentials");
  }
  if (!sameDocumentBase(url, allowedBase)) {
    throw new ProofError(
      "submission_out_of_scope",
      "the submitted proof URL is outside the configured entry document",
    );
  }
  return url;
}

async function readArtifactForProof(
  path: string,
  maxBytes: number,
  missingCode: ProofFailureCode,
  missingMessage: string,
): Promise<Buffer> {
  try {
    return await readRegularFile(path, maxBytes);
  } catch (error) {
    if (!(error instanceof ArtifactIssue)) throw error;
    switch (error.kind) {
      case "missing":
        throw new ProofError(missingCode, missingMessage);
      case "too-large":
        throw new ProofError("artifact_too_large", error.message);
      case "unsafe":
      case "changed":
        throw new ProofError("unsafe_artifact", error.message);
    }
  }
}

function decodeUtf8(bytes: Uint8Array, code: ProofFailureCode, message: string): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new ProofError(code, message);
  }
}

function containsControlCharacter(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (codePoint !== undefined && (codePoint < 0x20 || codePoint === 0x7f)) return true;
  }
  return false;
}
