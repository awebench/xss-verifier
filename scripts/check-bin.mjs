import { execFile } from "node:child_process";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

const execute = promisify(execFile);
const directory = await mkdtemp(join(tmpdir(), "xss-verifier-bin-"));

try {
  await execute("npm", ["pack", "--ignore-scripts", "--pack-destination", directory, "--quiet"]);
  const archive = (await readdir(directory)).find((entry) => entry.endsWith(".tgz"));
  if (!archive) throw new Error("npm pack did not produce an archive");

  const installation = join(directory, "installation");
  await execute("npm", [
    "install",
    "--prefix",
    installation,
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
    join(directory, archive),
  ]);
  const binary = resolve(installation, "node_modules/.bin/xss-verifier");
  const { stdout } = await execute(binary, ["--help"]);
  if (!stdout.startsWith("Usage: xss-verifier")) {
    throw new Error("installed binary did not print help");
  }
} finally {
  await rm(directory, { recursive: true, force: true });
}
