import { createServer } from "node:net";

import { afterEach, describe, expect, it } from "vitest";

import { startTaskServer, type RunningTaskServer } from "./task-server.js";

describe("trusted task server", () => {
  const running: RunningTaskServer[] = [];

  afterEach(async () => {
    await Promise.allSettled(running.splice(0).map(async (server) => server.close()));
  });

  it("starts from verified bytes with snapshot resource paths and waits for both origins", async () => {
    const inputs = await taskServerInputs(workingServer);
    const server = await startTaskServer(inputs);
    running.push(server);

    await expect(readText(inputs.victim.url)).resolves.toBe("victim snapshot");
    await expect(readText(inputs.attacker.url)).resolves.toBe("attacker snapshot");
    server.assertRunning();
  });

  it("fails when the server exits before becoming ready", async () => {
    const inputs = await taskServerInputs("process.exit(7);\n");

    await expect(
      startTaskServer(inputs, { startupTimeoutMs: 1000, shutdownTimeoutMs: 100 }),
    ).rejects.toThrowError(/exited before becoming ready \(code 7\)/u);
  });

  it("fails when both configured origins do not become ready", async () => {
    const inputs = await taskServerInputs("setInterval(() => {}, 1000);\n");

    await expect(
      startTaskServer(inputs, {
        startupTimeoutMs: 150,
        probeTimeoutMs: 25,
        shutdownTimeoutMs: 100,
      }),
    ).rejects.toThrowError(/did not make both configured origins ready within 150 ms/u);
  });

  it("requires both origins to remain available after the readiness delay", async () => {
    const inputs = await taskServerInputs(unstableReadinessServer);

    await expect(
      startTaskServer(inputs, {
        startupTimeoutMs: 250,
        probeTimeoutMs: 25,
        shutdownTimeoutMs: 100,
      }),
    ).rejects.toThrowError(/did not make both configured origins ready within 250 ms/u);
  });

  it("reports an unexpected exit after readiness", async () => {
    const inputs = await taskServerInputs(workingServer);
    const server = await startTaskServer(inputs);
    running.push(server);

    await fetch(`${inputs.victim.url.href}?exit=9`);
    await expect(server.waitForUnexpectedExit()).rejects.toThrowError(
      /exited during replay \(code 9\)/u,
    );
    expect(() => server.assertRunning()).toThrowError(/exited during replay \(code 9\)/u);
  });

  it("terminates the child and releases both listeners during teardown", async () => {
    const inputs = await taskServerInputs(workingServer);
    const server = await startTaskServer(inputs, { shutdownTimeoutMs: 500 });

    await server.close();
    await expect(canConnect(inputs.victim.url)).resolves.toBe(false);
    await expect(canConnect(inputs.attacker.url)).resolves.toBe(false);
  });

  it.skipIf(process.platform === "win32")(
    "terminates descendants after the server leader has exited",
    async () => {
      const inputs = await taskServerInputs(descendantTaskServer);
      const server = await startTaskServer(inputs, { shutdownTimeoutMs: 100 });
      running.push(server);

      await fetch(`${inputs.victim.url.href}?exit=9`);
      await expect(server.waitForUnexpectedExit()).rejects.toThrowError(
        /exited during replay \(code 9\)/u,
      );
      await expect(canConnect(inputs.attacker.url)).resolves.toBe(true);

      await server.close();
      await expect(canConnect(inputs.attacker.url)).resolves.toBe(false);
    },
  );
});

const workingServer = `
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";

const resources = [
  ["XSS_TASK_VICTIM_URL", "REPRODUCTION_FILE"],
  ["XSS_TASK_ATTACKER_URL", "ATTACKER_FILE"],
];

for (const [urlName, pathName] of resources) {
  const url = new URL(process.env[urlName]);
  createServer(async (request, response) => {
    const requestUrl = new URL(request.url ?? "/", url);
    if (requestUrl.pathname !== url.pathname) {
      response.writeHead(404).end();
      return;
    }
    if (requestUrl.searchParams.has("exit")) {
      response.end();
      setImmediate(() => process.exit(9));
      return;
    }
    const bytes = await readFile(process.env[pathName]);
    response.writeHead(200, { "Content-Type": "text/plain" }).end(bytes);
  }).listen(Number(url.port), url.hostname);
}
`;

const unstableReadinessServer = `
import { createServer } from "node:http";

const victim = new URL(process.env.XSS_TASK_VICTIM_URL);
const attacker = new URL(process.env.XSS_TASK_ATTACKER_URL);
createServer((_request, response) => response.writeHead(204).end())
  .listen(Number(victim.port), victim.hostname);
const unstable = createServer((_request, response) => {
  response.once("finish", () => unstable.close());
  response.writeHead(204).end();
});
unstable.listen(Number(attacker.port), attacker.hostname);
`;

const descendantCode = `
const { createServer } = require("node:http");
const url = new URL(process.env.DESCENDANT_URL);
process.on("SIGTERM", () => {});
createServer((_request, response) => response.writeHead(204).end())
  .listen(Number(url.port), url.hostname);
`;

const descendantTaskServer = `
import { spawn } from "node:child_process";
import { createServer } from "node:http";

const victim = new URL(process.env.XSS_TASK_VICTIM_URL);
const attacker = new URL(process.env.XSS_TASK_ATTACKER_URL);
spawn(process.execPath, ["-e", ${JSON.stringify(descendantCode)}], {
  env: { ...process.env, DESCENDANT_URL: attacker.href },
  stdio: "ignore",
});
createServer((request, response) => {
  const url = new URL(request.url ?? "/", victim);
  response.writeHead(204).end();
  if (url.searchParams.has("exit")) setImmediate(() => process.exit(9));
}).listen(Number(victim.port), victim.hostname);
`;

async function taskServerInputs(serverSource: string) {
  const victimPort = await freePort();
  const attackerPort = await freePort();
  return {
    serverBytes: Buffer.from(serverSource),
    victim: {
      path: "/source/victim.html",
      url: new URL(`http://127.0.0.1:${victimPort}/victim.html`),
      bytes: Buffer.from("victim snapshot"),
    },
    attacker: {
      path: "/source/attacker.html",
      url: new URL(`http://127.0.0.1:${attackerPort}/attacker.html`),
      bytes: Buffer.from("attacker snapshot"),
    },
  };
}

async function freePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("no TCP port allocated");
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
  return address.port;
}

async function readText(url: URL): Promise<string> {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`unexpected HTTP ${response.status}`);
  return response.text();
}

async function canConnect(url: URL): Promise<boolean> {
  try {
    await fetch(url);
    return true;
  } catch {
    return false;
  }
}
