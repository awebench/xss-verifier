import type { ProofFailureCode } from "./types.js";

export class ConfigError extends Error {
  override readonly name = "ConfigError";
}

export class TechnicalError extends Error {
  override readonly name = "TechnicalError";
}

export class ProofError extends Error {
  override readonly name = "ProofError";

  constructor(
    readonly reasonCode: ProofFailureCode,
    message: string,
  ) {
    super(message);
  }
}

export function errorMessage(value: unknown): string {
  return value instanceof Error ? value.message : String(value);
}

export function isNodeError(value: unknown): value is NodeJS.ErrnoException {
  return value instanceof Error && "code" in value;
}
