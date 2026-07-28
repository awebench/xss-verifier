import { spawn, type ChildProcess } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { errorMessage, isNodeError, TechnicalError } from "./errors.js";
import type { ResourceConfig } from "./types.js";

interface TaskServerInputs {
  serverBytes: Buffer;
  victim: ResourceConfig & { bytes: Buffer };
  attacker: ResourceConfig & { bytes?: Buffer };
}

interface TaskServerTiming {
  startupTimeoutMs?: number;
  probeTimeoutMs?: number;
  shutdownTimeoutMs?: number;
}

type TaskServerExit =
  | { kind: "error"; error: Error }
  | { kind: "exit"; code: number | null; signal: NodeJS.Signals | null };

export interface RunningTaskServer {
  assertRunning(): void;
  waitForUnexpectedExit(): Promise<never>;
  close(): Promise<void>;
}

const defaultStartupTimeoutMs = 5000;
const defaultProbeTimeoutMs = 250;
const defaultShutdownTimeoutMs = 1000;
const readinessPollMs = 50;
const readinessStabilityMs = 50;

export async function startTaskServer(
  inputs: TaskServerInputs,
  timing: TaskServerTiming = {},
): Promise<RunningTaskServer> {
  const directory = await mkdtemp(join(tmpdir(), "xss-verifier-task-server-"));
  const serverPath = join(directory, "server.mjs");
  const victimPath = join(directory, "victim.html");
  const attackerPath = join(directory, "attacker.html");
  let child: ChildProcess | undefined;
  let lifecycle: ReturnType<typeof observeChild> | undefined;

  try {
    await Promise.all([
      writeFile(serverPath, inputs.serverBytes, { flag: "wx", mode: 0o400 }),
      writeFile(victimPath, inputs.victim.bytes, { flag: "wx", mode: 0o400 }),
      ...(inputs.attacker.bytes === undefined
        ? []
        : [writeFile(attackerPath, inputs.attacker.bytes, { flag: "wx", mode: 0o400 })]),
    ]);

    const spawnedChild = spawn(process.execPath, [serverPath], {
      detached: process.platform !== "win32",
      env: {
        ...process.env,
        REPRODUCTION_FILE: victimPath,
        ATTACKER_FILE: attackerPath,
        XSS_TASK_VICTIM_PATH: victimPath,
        XSS_TASK_VICTIM_URL: inputs.victim.url.href,
        XSS_TASK_VICTIM_ORIGIN: inputs.victim.url.origin,
        XSS_TASK_ATTACKER_PATH: attackerPath,
        XSS_TASK_ATTACKER_URL: inputs.attacker.url.href,
        XSS_TASK_ATTACKER_ORIGIN: inputs.attacker.url.origin,
      },
      stdio: "ignore",
    });
    child = spawnedChild;
    const observedLifecycle = observeChild(spawnedChild);
    lifecycle = observedLifecycle;

    await waitUntilReady(
      [inputs.victim.url, inputs.attacker.url],
      observedLifecycle,
      timing.startupTimeoutMs ?? defaultStartupTimeoutMs,
      timing.probeTimeoutMs ?? defaultProbeTimeoutMs,
    );

    let closePromise: Promise<void> | undefined;
    return {
      assertRunning(): void {
        if (observedLifecycle.current !== undefined) {
          throw unexpectedExitError(observedLifecycle.current);
        }
      },
      waitForUnexpectedExit(): Promise<never> {
        return observedLifecycle.exited.then((exit) => {
          throw unexpectedExitError(exit);
        });
      },
      close(): Promise<void> {
        closePromise ??= stopAndCleanUp(
          spawnedChild,
          observedLifecycle.exited,
          directory,
          timing.shutdownTimeoutMs ?? defaultShutdownTimeoutMs,
        );
        return closePromise;
      },
    };
  } catch (error) {
    if (child !== undefined && lifecycle !== undefined) {
      await stopChild(
        child,
        lifecycle.exited,
        timing.shutdownTimeoutMs ?? defaultShutdownTimeoutMs,
      ).catch(() => {});
    }
    await rm(directory, { recursive: true, force: true }).catch(() => {});
    if (error instanceof TechnicalError) throw error;
    throw new TechnicalError(`cannot start trusted task server: ${errorMessage(error)}`, {
      cause: error,
    });
  }
}

function observeChild(child: ChildProcess): {
  readonly exited: Promise<TaskServerExit>;
  readonly current: TaskServerExit | undefined;
} {
  let current: TaskServerExit | undefined;
  const exited = new Promise<TaskServerExit>((resolve) => {
    const settle = (exit: TaskServerExit): void => {
      if (current !== undefined) return;
      current = exit;
      resolve(exit);
    };
    child.once("error", (error) => settle({ kind: "error", error }));
    child.once("exit", (code, signal) => settle({ kind: "exit", code, signal }));
  });
  return {
    exited,
    get current() {
      return current;
    },
  };
}

async function waitUntilReady(
  urls: readonly URL[],
  lifecycle: ReturnType<typeof observeChild>,
  startupTimeoutMs: number,
  probeTimeoutMs: number,
): Promise<void> {
  const deadline = Date.now() + startupTimeoutMs;
  while (Date.now() < deadline) {
    const probe = Promise.all(
      urls.map(async (url) => probeHttp(url, Math.min(probeTimeoutMs, remaining(deadline)))),
    ).then((results) => results.every(Boolean));
    const result = await Promise.race([
      probe.then((ready) => ({ kind: "probe" as const, ready })),
      lifecycle.exited.then((exit) => ({ kind: "exit" as const, exit })),
    ]);
    if (result.kind === "exit") throw startupExitError(result.exit);
    if (result.ready) {
      await Promise.race([
        delay(Math.min(readinessStabilityMs, remaining(deadline))),
        lifecycle.exited.then((exit) => {
          throw startupExitError(exit);
        }),
      ]);
      const stable = await probeWhileRunning(urls, lifecycle, deadline, probeTimeoutMs);
      if (stable) return;
    }
    await Promise.race([
      delay(Math.min(readinessPollMs, remaining(deadline))),
      lifecycle.exited.then((exit) => {
        throw startupExitError(exit);
      }),
    ]);
  }
  throw new TechnicalError(
    `trusted task server did not make both configured origins ready within ${startupTimeoutMs} ms`,
  );
}

async function probeWhileRunning(
  urls: readonly URL[],
  lifecycle: ReturnType<typeof observeChild>,
  deadline: number,
  probeTimeoutMs: number,
): Promise<boolean> {
  const probe = Promise.all(
    urls.map(async (url) => probeHttp(url, Math.min(probeTimeoutMs, remaining(deadline)))),
  ).then((results) => results.every(Boolean));
  const result = await Promise.race([
    probe.then((ready) => ({ kind: "probe" as const, ready })),
    lifecycle.exited.then((exit) => ({ kind: "exit" as const, exit })),
  ]);
  if (result.kind === "exit") throw startupExitError(result.exit);
  return result.ready;
}

function probeHttp(url: URL, timeoutMs: number): Promise<boolean> {
  if (timeoutMs <= 0) return Promise.resolve(false);
  return new Promise((resolve) => {
    const probe = request(url, { method: "GET" }, (response) => {
      response.resume();
      resolve(true);
    });
    const timer = setTimeout(() => probe.destroy(), timeoutMs);
    probe.once("close", () => clearTimeout(timer));
    probe.once("error", () => resolve(false));
    probe.end();
  });
}

async function stopAndCleanUp(
  child: ChildProcess,
  exited: Promise<TaskServerExit>,
  directory: string,
  shutdownTimeoutMs: number,
): Promise<void> {
  try {
    await stopChild(child, exited, shutdownTimeoutMs);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function stopChild(
  child: ChildProcess,
  exited: Promise<TaskServerExit>,
  shutdownTimeoutMs: number,
): Promise<void> {
  if (process.platform === "win32") {
    await stopWindowsChild(child, exited, shutdownTimeoutMs);
  } else {
    await stopPosixProcessGroup(child, shutdownTimeoutMs);
  }
}

async function stopWindowsChild(
  child: ChildProcess,
  exited: Promise<TaskServerExit>,
  shutdownTimeoutMs: number,
): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  signalWindowsChild(child, "SIGTERM");
  if (await settlesWithin(exited, shutdownTimeoutMs)) return;
  signalWindowsChild(child, "SIGKILL");
  if (!(await settlesWithin(exited, shutdownTimeoutMs))) {
    throw new TechnicalError("trusted task server did not exit after SIGKILL");
  }
}

async function stopPosixProcessGroup(
  child: ChildProcess,
  shutdownTimeoutMs: number,
): Promise<void> {
  const pid = child.pid;
  if (pid === undefined) {
    throw new TechnicalError("trusted task server has no process group identifier");
  }
  if (!processGroupExists(pid)) return;

  signalProcessGroup(pid, "SIGTERM");
  if (await conditionWithin(() => !processGroupExists(pid), shutdownTimeoutMs)) return;
  signalProcessGroup(pid, "SIGKILL");
  if (!(await conditionWithin(() => !processGroupExists(pid), shutdownTimeoutMs))) {
    throw new TechnicalError("trusted task server process group remains after SIGKILL");
  }
}

function signalWindowsChild(child: ChildProcess, signal: NodeJS.Signals): void {
  try {
    child.kill(signal);
  } catch (error) {
    if (isNodeError(error) && error.code === "ESRCH") return;
    throw new TechnicalError(
      `cannot send ${signal} to trusted task server: ${errorMessage(error)}`,
      { cause: error },
    );
  }
}

function signalProcessGroup(pid: number, signal: NodeJS.Signals): void {
  try {
    process.kill(-pid, signal);
  } catch (error) {
    if (isNodeError(error) && error.code === "ESRCH") return;
    throw new TechnicalError(
      `cannot send ${signal} to trusted task server process group: ${errorMessage(error)}`,
      { cause: error },
    );
  }
}

function processGroupExists(pid: number): boolean {
  try {
    process.kill(-pid, 0);
    return true;
  } catch (error) {
    if (isNodeError(error) && error.code === "ESRCH") return false;
    if (isNodeError(error) && error.code === "EPERM") return true;
    throw new TechnicalError(
      `cannot inspect trusted task server process group: ${errorMessage(error)}`,
      { cause: error },
    );
  }
}

async function conditionWithin(condition: () => boolean, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (condition()) return true;
    await delay(Math.min(25, remaining(deadline)));
  }
  return condition();
}

function settlesWithin(promise: Promise<unknown>, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), timeoutMs);
    void promise.then(() => {
      clearTimeout(timer);
      resolve(true);
    });
  });
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, Math.max(0, milliseconds)));
}

function remaining(deadline: number): number {
  return Math.max(0, deadline - Date.now());
}

function startupExitError(exit: TaskServerExit): TechnicalError {
  return new TechnicalError(
    `trusted task server exited before becoming ready (${describeExit(exit)})`,
  );
}

function unexpectedExitError(exit: TaskServerExit): TechnicalError {
  return new TechnicalError(`trusted task server exited during replay (${describeExit(exit)})`);
}

function describeExit(exit: TaskServerExit): string {
  if (exit.kind === "error") return errorMessage(exit.error);
  if (exit.signal !== null) return `signal ${exit.signal}`;
  return `code ${String(exit.code)}`;
}
