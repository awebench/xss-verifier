import { isIP } from "node:net";

import { ConfigError } from "./errors.js";

export function parseConfiguredUrl(value: string, field: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ConfigError(`${field} must be an absolute URL`);
  }

  if (url.username || url.password) {
    throw new ConfigError(`${field} must not contain credentials`);
  }
  if (url.protocol !== "http:") {
    throw new ConfigError(`${field} must use loopback http:`);
  }

  if (!isLoopbackHostname(url.hostname)) {
    throw new ConfigError(`${field} HTTP host must be loopback`);
  }
  const port = Number(url.port);
  if (!url.port || !Number.isInteger(port) || port < 1024 || port > 65_535) {
    throw new ConfigError(`${field} must declare an unprivileged loopback port`);
  }
  return url;
}

function isLoopbackHostname(hostname: string): boolean {
  const bare =
    hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
  if (bare === "localhost" || bare === "::1") return true;
  return isIP(bare) === 4 && bare.startsWith("127.");
}

export function sameDocumentBase(candidate: URL, allowed: URL): boolean {
  return (
    candidate.protocol === allowed.protocol &&
    candidate.username === "" &&
    candidate.password === "" &&
    candidate.hostname === allowed.hostname &&
    candidate.port === allowed.port &&
    candidate.pathname === allowed.pathname
  );
}

export function expectedSecurityOrigin(url: URL): string {
  return url.origin;
}

export function truncateEvidence(value: string, limit: number): string {
  if (value.length <= limit) return value;
  return `${value.slice(0, Math.max(0, limit - 1))}…`;
}
