import {
  createInvocation,
  helpText,
  parseArguments,
  parseOutputSelection,
  parseVerifierConfig,
} from "./config.js";
import { ConfigError, errorMessage } from "./errors.js";
import { prepareHarborOutput, writeHarborResult } from "./output.js";
import { verify } from "./replay.js";

interface OutputStream {
  write(value: string): unknown;
}

export interface CliIo {
  stdout: OutputStream;
  stderr: OutputStream;
  now(): number;
}

const processIo: CliIo = {
  stdout: process.stdout,
  stderr: process.stderr,
  now: Date.now,
};

export async function main(
  args: readonly string[] = process.argv.slice(2),
  environment: NodeJS.ProcessEnv = process.env,
  io: CliIo = processIo,
): Promise<number> {
  try {
    const parsed = parseArguments(args);
    if (parsed.help) {
      io.stdout.write(helpText);
      return 0;
    }

    const output = parseOutputSelection(parsed, environment);
    if (output.kind === "harbor") {
      await prepareHarborOutput(output.outputDirectory);
    }
    const config = parseVerifierConfig(parsed, environment);
    const invocation = createInvocation(output, config);
    const start = io.now();
    const result = await verify(invocation.config);
    const stop = io.now();

    switch (invocation.kind) {
      case "json":
        io.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
        return result.passed ? 0 : 1;
      case "harbor":
        await writeHarborResult(invocation.outputDirectory, result, { start, stop });
        io.stdout.write(`${JSON.stringify(result)}\n`);
        return 0;
    }
  } catch (error) {
    const failure =
      error instanceof ConfigError
        ? {
            schemaVersion: "xss-verifier-error-v1",
            kind: "configuration",
            reasonCode: "invalid_configuration",
            reason: errorMessage(error),
          }
        : {
            schemaVersion: "xss-verifier-error-v1",
            kind: "technical",
            reasonCode: "technical_failure",
            reason: errorMessage(error),
          };
    io.stderr.write(`${JSON.stringify(failure)}\n`);
    return 2;
  }
}
