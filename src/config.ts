import { parseArgs } from "node:util";

import { z } from "zod";

import { ConfigError, errorMessage } from "./errors.js";
import { dialogTypes, type Invocation, type VerifierConfig } from "./types.js";
import { parseConfiguredUrl } from "./urls.js";

type EnvironmentName = `XSS_VERIFIER_${string}`;

function defineOption<const Schema extends z.ZodType>(definition: {
  cli: string;
  environment: EnvironmentName;
  valueName: string;
  description: string;
  required?: boolean;
  schema: Schema;
}) {
  return definition;
}

function integerString(min: number, max: number) {
  return z
    .string()
    .regex(/^\d+$/u, "must be an integer")
    .transform(Number)
    .refine((value) => Number.isSafeInteger(value) && value >= min && value <= max, {
      message: `must be between ${min} and ${max}`,
    });
}

const optionDefinitions = {
  adapter: defineOption({
    cli: "adapter",
    environment: "XSS_VERIFIER_ADAPTER",
    valueName: "json|harbor",
    description: "Output adapter (default: json)",
    schema: z.enum(["json", "harbor"]).default("json"),
  }),
  outputDirectory: defineOption({
    cli: "output-directory",
    environment: "XSS_VERIFIER_OUTPUT_DIRECTORY",
    valueName: "PATH",
    description: "Harbor artifact directory",
    schema: z.string().min(1).optional(),
  }),
  submissionPath: defineOption({
    cli: "submission-path",
    environment: "XSS_VERIFIER_SUBMISSION_PATH",
    valueName: "PATH",
    description: "Submitted proof URL file",
    required: true,
    schema: z.string().min(1),
  }),
  victimPath: defineOption({
    cli: "victim-path",
    environment: "XSS_VERIFIER_VICTIM_PATH",
    valueName: "PATH",
    description: "Trusted victim HTML artifact",
    required: true,
    schema: z.string().min(1),
  }),
  victimUrl: defineOption({
    cli: "victim-url",
    environment: "XSS_VERIFIER_VICTIM_URL",
    valueName: "URL",
    description: "Loopback HTTP URL for the victim",
    required: true,
    schema: z.string().min(1),
  }),
  victimSha256: defineOption({
    cli: "victim-sha256",
    environment: "XSS_VERIFIER_VICTIM_SHA256",
    valueName: "HEX",
    description: "Lowercase SHA-256 of the victim",
    required: true,
    schema: z.string().regex(/^[a-f0-9]{64}$/u, "must be a lowercase SHA-256 digest"),
  }),
  attackerPath: defineOption({
    cli: "attacker-path",
    environment: "XSS_VERIFIER_ATTACKER_PATH",
    valueName: "PATH",
    description: "Optional submitted attacker HTML artifact",
    required: true,
    schema: z.string().min(1),
  }),
  attackerUrl: defineOption({
    cli: "attacker-url",
    environment: "XSS_VERIFIER_ATTACKER_URL",
    valueName: "URL",
    description: "Loopback HTTP URL for an attacker page",
    required: true,
    schema: z.string().min(1),
  }),
  dialogType: defineOption({
    cli: "dialog-type",
    environment: "XSS_VERIFIER_DIALOG_TYPE",
    valueName: "alert|confirm|prompt",
    description: "Expected JavaScript dialog type",
    required: true,
    schema: z.enum(dialogTypes),
  }),
  dialogMessage: defineOption({
    cli: "dialog-message",
    environment: "XSS_VERIFIER_DIALOG_MESSAGE",
    valueName: "TEXT",
    description: "Exact expected dialog message",
    required: true,
    schema: z.string().max(4096, "must not exceed 4096 characters"),
  }),
  frameScope: defineOption({
    cli: "frame-scope",
    environment: "XSS_VERIFIER_FRAME_SCOPE",
    valueName: "top|any",
    description: "Allowed victim frame scope",
    required: true,
    schema: z.enum(["top", "any"]),
  }),
  timeoutMs: defineOption({
    cli: "timeout-ms",
    environment: "XSS_VERIFIER_TIMEOUT_MS",
    valueName: "MILLISECONDS",
    description: "Replay deadline (100-30000)",
    required: true,
    schema: integerString(100, 30_000),
  }),
  browserPath: defineOption({
    cli: "browser-path",
    environment: "XSS_VERIFIER_BROWSER_PATH",
    valueName: "PATH",
    description: "Chrome executable",
    required: true,
    schema: z.string().min(1),
  }),
  browserVersion: defineOption({
    cli: "expected-browser-version",
    environment: "XSS_VERIFIER_EXPECTED_BROWSER_VERSION",
    valueName: "VERSION",
    description: "Exact expected Chrome version",
    required: true,
    schema: z.string().min(1),
  }),
  browserSandbox: defineOption({
    cli: "browser-sandbox",
    environment: "XSS_VERIFIER_BROWSER_SANDBOX",
    valueName: "enabled|disabled",
    description: "Chromium renderer sandbox mode (default: enabled)",
    schema: z.enum(["enabled", "disabled"]).default("enabled"),
  }),
  submissionBytes: defineOption({
    cli: "max-submission-bytes",
    environment: "XSS_VERIFIER_MAX_SUBMISSION_BYTES",
    valueName: "BYTES",
    description: "Maximum submission size (default: 16384)",
    schema: integerString(128, 1024 * 1024).default(16 * 1024),
  }),
  attackerBytes: defineOption({
    cli: "max-attacker-bytes",
    environment: "XSS_VERIFIER_MAX_ATTACKER_BYTES",
    valueName: "BYTES",
    description: "Maximum attacker page size (default: 262144)",
    schema: integerString(128, 4 * 1024 * 1024).default(256 * 1024),
  }),
  dialogs: defineOption({
    cli: "max-dialogs",
    environment: "XSS_VERIFIER_MAX_DIALOGS",
    valueName: "COUNT",
    description: "Maximum recorded dialogs (default: 64)",
    schema: integerString(1, 1024).default(64),
  }),
  pages: defineOption({
    cli: "max-pages",
    environment: "XSS_VERIFIER_MAX_PAGES",
    valueName: "COUNT",
    description: "Maximum recorded final pages (default: 64)",
    schema: integerString(1, 1024).default(64),
  }),
  evidenceCharacters: defineOption({
    cli: "max-evidence-characters",
    environment: "XSS_VERIFIER_MAX_EVIDENCE_CHARACTERS",
    valueName: "COUNT",
    description: "Maximum characters per evidence value (default: 4096)",
    schema: integerString(128, 65_536).default(4096),
  }),
} as const;

type OptionKey = keyof typeof optionDefinitions;

export interface ParsedArguments {
  help: boolean;
  values: ReadonlyMap<OptionKey, string>;
}

export type OutputSelection = { kind: "json" } | { kind: "harbor"; outputDirectory: string };

const cliOptions = Object.fromEntries([
  ...Object.values(optionDefinitions).map((definition) => [
    definition.cli,
    { type: "string" as const },
  ]),
  ["help", { type: "boolean" as const, short: "h" }],
]);

export const helpText = `${[
  "Usage: xss-verifier [options]",
  "",
  "Options may also be supplied through the matching XSS_VERIFIER_* environment variable.",
  "CLI flags take precedence.",
  "",
  ...Object.values(optionDefinitions).map(
    (definition) =>
      `  --${definition.cli} ${definition.valueName}`.padEnd(48) + definition.description,
  ),
  "  -h, --help".padEnd(48) + "Show this help",
].join("\n")}\n`;

export function parseArguments(args: readonly string[]): ParsedArguments {
  try {
    const parsed = parseArgs({
      args: [...args],
      options: cliOptions,
      strict: true,
      allowPositionals: false,
    });
    const parsedValues = parsed.values as Record<string, string | boolean | undefined>;
    const values = new Map<OptionKey, string>();
    for (const [key, definition] of Object.entries(optionDefinitions) as [
      OptionKey,
      (typeof optionDefinitions)[OptionKey],
    ][]) {
      const value = parsedValues[definition.cli];
      if (typeof value === "string") values.set(key, value);
    }
    return { help: parsedValues.help === true, values };
  } catch (error) {
    throw new ConfigError(errorMessage(error), { cause: error });
  }
}

function configuredValue(
  key: OptionKey,
  parsed: ParsedArguments,
  environment: NodeJS.ProcessEnv,
): string | undefined {
  const cliValue = parsed.values.get(key);
  if (cliValue !== undefined) return cliValue;
  return environment[optionDefinitions[key].environment];
}

function parseOption<Key extends OptionKey>(
  key: Key,
  parsed: ParsedArguments,
  environment: NodeJS.ProcessEnv,
): z.output<(typeof optionDefinitions)[Key]["schema"]> {
  const definition = optionDefinitions[key];
  const raw = configuredValue(key, parsed, environment);
  if (raw === undefined && definition.required === true) {
    throw new ConfigError(`${definition.environment} is required`);
  }
  const result = definition.schema.safeParse(raw);
  if (!result.success) {
    const message = result.error.issues[0]?.message ?? "is invalid";
    throw new ConfigError(`${definition.environment} ${message}`);
  }
  return result.data as z.output<(typeof optionDefinitions)[Key]["schema"]>;
}

export function parseOutputSelection(
  parsed: ParsedArguments,
  environment: NodeJS.ProcessEnv = process.env,
): OutputSelection {
  const adapter = parseOption("adapter", parsed, environment);
  const outputDirectory = parseOption("outputDirectory", parsed, environment);
  if (adapter === "json") {
    if (outputDirectory !== undefined) {
      throw new ConfigError("XSS_VERIFIER_OUTPUT_DIRECTORY requires the Harbor adapter");
    }
    return { kind: "json" };
  }
  if (outputDirectory === undefined) {
    throw new ConfigError("XSS_VERIFIER_OUTPUT_DIRECTORY is required for the Harbor adapter");
  }
  return { kind: "harbor", outputDirectory };
}

export function parseVerifierConfig(
  parsed: ParsedArguments,
  environment: NodeJS.ProcessEnv = process.env,
): VerifierConfig {
  const victimUrl = parseConfiguredUrl(
    parseOption("victimUrl", parsed, environment),
    "XSS_VERIFIER_VICTIM_URL",
  );
  const attackerUrl = parseConfiguredUrl(
    parseOption("attackerUrl", parsed, environment),
    "XSS_VERIFIER_ATTACKER_URL",
  );
  if (attackerUrl.origin === victimUrl.origin) {
    throw new ConfigError("attacker and victim must use distinct origins");
  }

  return {
    submissionPath: parseOption("submissionPath", parsed, environment),
    victim: {
      path: parseOption("victimPath", parsed, environment),
      url: victimUrl,
      sha256: parseOption("victimSha256", parsed, environment),
    },
    attacker: {
      path: parseOption("attackerPath", parsed, environment),
      url: attackerUrl,
    },
    expectation: {
      dialogType: parseOption("dialogType", parsed, environment),
      message: parseOption("dialogMessage", parsed, environment),
      frameScope: parseOption("frameScope", parsed, environment),
    },
    browser: {
      executablePath: parseOption("browserPath", parsed, environment),
      expectedVersion: parseOption("browserVersion", parsed, environment),
      sandbox: parseOption("browserSandbox", parsed, environment),
    },
    timeoutMs: parseOption("timeoutMs", parsed, environment),
    limits: {
      submissionBytes: parseOption("submissionBytes", parsed, environment),
      attackerBytes: parseOption("attackerBytes", parsed, environment),
      dialogs: parseOption("dialogs", parsed, environment),
      pages: parseOption("pages", parsed, environment),
      characters: parseOption("evidenceCharacters", parsed, environment),
    },
  };
}

export function createInvocation(output: OutputSelection, config: VerifierConfig): Invocation {
  switch (output.kind) {
    case "json":
      return { kind: "json", config };
    case "harbor":
      return { kind: "harbor", config, outputDirectory: output.outputDirectory };
  }
}

export function parseInvocation(
  args: readonly string[],
  environment: NodeJS.ProcessEnv = process.env,
): { kind: "help" } | { kind: "run"; invocation: Invocation } {
  const parsed = parseArguments(args);
  if (parsed.help) return { kind: "help" };
  const output = parseOutputSelection(parsed, environment);
  const config = parseVerifierConfig(parsed, environment);
  return { kind: "run", invocation: createInvocation(output, config) };
}
