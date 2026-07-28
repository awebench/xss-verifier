import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import puppeteer, { type Browser, type ElementHandle, type Page } from "puppeteer-core";

import { DialogObserver } from "./browser.js";
import { errorMessage, ProofError, TechnicalError } from "./errors.js";
import { readAttackerPage, readSubmission, readTrustedServer, readTrustedVictim } from "./files.js";
import { verificationFailure, verificationSuccess } from "./results.js";
import { serveResource, type RunningServer } from "./server.js";
import { startTaskServer, type RunningTaskServer } from "./task-server.js";
import type {
  InteractionEvidence,
  ResourceConfig,
  VerificationEvidence,
  VerificationResult,
  VerifierConfig,
} from "./types.js";
import { sameDocumentBase, truncateEvidence } from "./urls.js";

type ReplayInputs =
  | ({
      kind: "navigation";
      victimBytes: Buffer;
      submission: URL;
    } & TrustedServerInput)
  | ({
      kind: "attacker-page";
      victimBytes: Buffer;
      attackerBytes: Buffer;
      submission: URL;
      attacker: ResourceConfig;
    } & TrustedServerInput);

type TrustedServerInput = { serverBytes?: Buffer };

type ReplayResult = {
  navigationError: string | null;
  interaction: InteractionEvidence;
};

type ClickResult = "none" | "clicked" | "failed";

const buttonSelector = "button";
const nativeClickTimeoutMs = 1_000;
const replayPollMs = 50;
const replayPassDelayMs = 250;

export async function verify(config: VerifierConfig): Promise<VerificationResult> {
  let replayKind: ReplayInputs["kind"] | null = null;
  let submittedUrl = "";
  let browserVersion = "";
  let browser: Browser | undefined;
  let observer: DialogObserver | undefined;
  let profile: string | undefined;
  let taskServer: RunningTaskServer | undefined;
  const servers: RunningServer[] = [];

  try {
    let inputs: ReplayInputs;
    try {
      inputs = await loadReplayInputs(config);
    } catch (error) {
      if (error instanceof ProofError) {
        return verificationFailure(error.reasonCode, error.message, emptyEvidence(replayKind));
      }
      throw error;
    }
    replayKind = inputs.kind;
    submittedUrl = inputs.submission.href;

    if (inputs.serverBytes !== undefined) {
      taskServer = await startTaskServer({
        serverBytes: inputs.serverBytes,
        victim: { ...config.victim, bytes: inputs.victimBytes },
        attacker: {
          ...config.attacker,
          ...(inputs.kind === "attacker-page" ? { bytes: inputs.attackerBytes } : {}),
        },
      });
    } else {
      servers.push(await serveResource(config.victim.url, inputs.victimBytes));
      if (inputs.kind === "attacker-page") {
        servers.push(await serveResource(inputs.attacker.url, inputs.attackerBytes));
      }
    }

    profile = await mkdtemp(join(tmpdir(), "xss-verifier-"));
    try {
      browser = await puppeteer.launch({
        executablePath: config.browser.executablePath,
        headless: true,
        userDataDir: profile,
        protocolTimeout: Math.max(30_000, config.timeoutMs + 10_000),
        args: [
          ...(config.browser.sandbox === "disabled" ? ["--no-sandbox"] : []),
          "--disable-background-networking",
          "--disable-component-update",
          "--disable-default-apps",
          "--disable-dev-shm-usage",
          "--disable-extensions",
          "--disable-features=Translate,MediaRouter",
          "--disable-sync",
          "--metrics-recording-only",
          "--no-first-run",
        ],
      });
    } catch (error) {
      throw new TechnicalError(`cannot launch the configured browser: ${errorMessage(error)}`, {
        cause: error,
      });
    }

    taskServer?.assertRunning();
    browserVersion = await browser.version();
    if (browserVersion !== `Chrome/${config.browser.expectedVersion}`) {
      throw new TechnicalError(
        `unexpected browser version ${browserVersion}; expected Chrome/${config.browser.expectedVersion}`,
      );
    }

    const pages = await browser.pages();
    const entryPage = pages[0] ?? (await browser.newPage());
    observer = new DialogObserver(browser, config);
    await observer.start();

    entryPage.setDefaultTimeout(Math.min(15_000, Math.max(1_000, config.timeoutMs)));
    const replay = navigateAndInteract(browser, entryPage, inputs.submission, observer, config);
    const replayResult =
      taskServer === undefined
        ? await replay
        : await Promise.race([replay, taskServer.waitForUnexpectedExit()]);
    const matchingDialog = observer.match;
    const finalPages = await browser.pages();
    taskServer?.assertRunning();
    const finalUrls = finalPages
      .slice(0, config.limits.pages)
      .map((page) => truncateEvidence(page.url(), config.limits.characters));
    const evidence: VerificationEvidence = {
      replayKind,
      interaction: replayResult.interaction,
      submittedUrl: truncateEvidence(submittedUrl, config.limits.characters),
      browserVersion,
      dialogs: [...observer.dialogs],
      matchingDialog,
      dialogLimitReached: observer.dialogLimitReached,
      finalUrls,
      pageLimitReached: finalPages.length > finalUrls.length,
      navigationError: replayResult.navigationError,
    };

    if (matchingDialog) {
      return verificationSuccess(
        "the configured dialog was observed in the victim document",
        evidence,
      );
    }
    if (observer.dialogs.length > 0 || observer.dialogLimitReached) {
      return verificationFailure(
        "dialog_mismatch",
        "browser dialogs were observed, but none matched the configured expectation",
        evidence,
      );
    }
    if (replayResult.navigationError) {
      return verificationFailure(
        "navigation_failed",
        "the submitted proof URL did not load",
        evidence,
      );
    }
    return verificationFailure(
      "dialog_timeout",
      "no matching browser dialog was observed before timeout",
      evidence,
    );
  } finally {
    observer?.stop();
    if (browser) await closeBrowser(browser);
    await cleanUpReplayResources(servers, taskServer, profile);
  }
}

export async function closeBrowser(browser: Browser, timeoutMs = 5_000): Promise<void> {
  let timedOut = false;
  let timeout: NodeJS.Timeout | undefined;
  const close = browser.close().catch(() => {});
  await Promise.race([
    close,
    new Promise<void>((resolve) => {
      timeout = setTimeout(() => {
        timedOut = true;
        resolve();
      }, timeoutMs);
    }),
  ]);
  if (timeout) clearTimeout(timeout);
  if (!timedOut) return;
  browser.process()?.kill("SIGKILL");
}

async function cleanUpReplayResources(
  staticServers: readonly RunningServer[],
  taskServer: RunningTaskServer | undefined,
  profile: string | undefined,
): Promise<void> {
  let serverCloseError: Error | undefined;
  try {
    await closeReplayServers(staticServers, taskServer);
  } catch (error) {
    serverCloseError =
      error instanceof Error
        ? error
        : new TechnicalError(`cannot stop replay servers: ${errorMessage(error)}`);
  }

  try {
    if (profile) await rm(profile, { recursive: true, force: true });
  } catch (error) {
    if (serverCloseError === undefined) {
      throw error instanceof Error
        ? error
        : new TechnicalError(`cannot remove browser profile: ${errorMessage(error)}`);
    }
  }
  if (serverCloseError !== undefined) throw serverCloseError;
}

export async function closeReplayServers(
  staticServers: readonly RunningServer[],
  taskServer: RunningTaskServer | undefined,
): Promise<void> {
  const results = await Promise.allSettled([
    ...staticServers.map(async (server) => server.close()),
    ...(taskServer === undefined ? [] : [taskServer.close()]),
  ]);
  if (taskServer === undefined) return;
  const taskServerResult = results[staticServers.length];
  if (taskServerResult?.status === "rejected") {
    throw new TechnicalError(
      `cannot stop trusted task server: ${errorMessage(taskServerResult.reason)}`,
      { cause: taskServerResult.reason },
    );
  }
}

async function navigateAndInteract(
  browser: Browser,
  page: Page,
  submission: URL,
  observer: DialogObserver,
  config: VerifierConfig,
): Promise<ReplayResult> {
  const interaction: InteractionEvidence = {
    attemptedClicks: 0,
    successfulClicks: 0,
    failedClicks: 0,
  };
  const deadline = Date.now() + config.timeoutMs;
  let navigationError: string | null = null;

  const navigation = page
    .goto(submission.href, {
      waitUntil: "load",
      timeout: Math.min(15_000, Math.max(1_000, config.timeoutMs)),
    })
    .then(() => null)
    .catch((error: unknown) => boundedError(error, config.limits.characters));
  const firstMatch = observer.waitForMatch(remainingTime(deadline));
  const initialResult = await Promise.race([
    navigation.then((error) => ({ kind: "navigation" as const, error })),
    firstMatch.then((match) => ({ kind: "dialog" as const, match })),
  ]);

  if (initialResult.kind === "dialog" && initialResult.match) {
    return { navigationError: null, interaction };
  }
  if (initialResult.kind === "navigation") {
    navigationError = initialResult.error;
  } else {
    return { navigationError, interaction };
  }

  while (remainingTime(deadline) > 0 && !observer.match) {
    const clickResult = await clickNextButton(
      browser,
      config.limits.pages,
      Math.min(nativeClickTimeoutMs, remainingTime(deadline)),
    );
    let waitMs = replayPollMs;
    if (clickResult !== "none") {
      interaction.attemptedClicks += 1;
      if (clickResult === "clicked") interaction.successfulClicks += 1;
      else interaction.failedClicks += 1;
    } else {
      await resetClaimedButtons(browser, config.limits.pages);
      waitMs = replayPassDelayMs;
    }
    await observer.waitForMatch(Math.min(waitMs, remainingTime(deadline)));
  }

  return { navigationError, interaction };
}

async function clickNextButton(
  browser: Browser,
  pageLimit: number,
  clickTimeoutMs: number,
): Promise<ClickResult> {
  const pages = (await browser.pages()).slice(0, pageLimit);
  for (const page of pages) {
    if (page.isClosed()) continue;
    for (const frame of page.frames()) {
      let buttons: ElementHandle<HTMLButtonElement>[];
      try {
        buttons = await frame.$$(buttonSelector);
      } catch {
        continue;
      }
      try {
        for (const button of buttons) {
          try {
            if (!(await button.isVisible()) || !(await claimButton(button))) continue;
            return (await activateButton(button, clickTimeoutMs)) ? "clicked" : "failed";
          } catch {
            return "failed";
          }
        }
      } finally {
        await Promise.allSettled(buttons.map(async (button) => button.dispose()));
      }
    }
  }
  return "none";
}

export async function activateButton(
  button: ElementHandle<HTMLButtonElement>,
  timeoutMs = nativeClickTimeoutMs,
): Promise<boolean> {
  const nativeClick = button.click().then(
    () => "clicked" as const,
    () => "failed" as const,
  );
  let timeout: NodeJS.Timeout | undefined;
  const result = await Promise.race([
    nativeClick,
    new Promise<"timed-out">((resolve) => {
      timeout = setTimeout(() => resolve("timed-out"), timeoutMs);
    }),
  ]);
  if (timeout) clearTimeout(timeout);
  if (result === "clicked") {
    return true;
  }
  const domActivation = button
    .evaluate((element) => {
      if (!element.isConnected || element.disabled) return false;
      element.click();
      return true;
    })
    .catch(() => false);
  let domTimeout: NodeJS.Timeout | undefined;
  const activated = await Promise.race([
    domActivation,
    new Promise<false>((resolve) => {
      domTimeout = setTimeout(() => resolve(false), timeoutMs);
    }),
  ]);
  if (domTimeout) clearTimeout(domTimeout);
  return activated;
}

async function claimButton(button: ElementHandle<HTMLButtonElement>): Promise<boolean> {
  return button.evaluate((element) => {
    if (element.disabled) return false;
    const key = Symbol.for("xss-verifier.clicked-buttons");
    const state = globalThis as typeof globalThis & {
      [key: symbol]: WeakSet<Element> | undefined;
    };
    const clicked = state[key] ?? new WeakSet<Element>();
    state[key] = clicked;
    if (clicked.has(element)) return false;
    clicked.add(element);
    return true;
  });
}

async function resetClaimedButtons(browser: Browser, pageLimit: number): Promise<void> {
  const pages = (await browser.pages()).slice(0, pageLimit);
  await Promise.allSettled(
    pages.flatMap((page) =>
      page.frames().map(async (frame) => {
        await frame.evaluate(() => {
          const key = Symbol.for("xss-verifier.clicked-buttons");
          const state = globalThis as typeof globalThis & {
            [key: symbol]: WeakSet<Element> | undefined;
          };
          state[key] = new WeakSet<Element>();
        });
      }),
    ),
  );
}

async function loadReplayInputs(config: VerifierConfig): Promise<ReplayInputs> {
  const [victimBytes, submission, serverBytes] = await Promise.all([
    readTrustedVictim(config.victim.path, config.victim.sha256),
    readSubmission(
      config.submissionPath,
      [config.victim.url, config.attacker.url],
      config.limits.submissionBytes,
    ),
    config.server === undefined
      ? Promise.resolve(undefined)
      : readTrustedServer(config.server.path, config.server.sha256),
  ]);
  const trustedServer = serverBytes === undefined ? {} : { serverBytes };
  if (sameDocumentBase(submission, config.victim.url)) {
    return { kind: "navigation", victimBytes, submission, ...trustedServer };
  }

  const attackerBytes = await readAttackerPage(config.attacker.path, config.limits.attackerBytes);
  return {
    kind: "attacker-page",
    victimBytes,
    attackerBytes,
    submission,
    attacker: config.attacker,
    ...trustedServer,
  };
}

function emptyEvidence(replayKind: ReplayInputs["kind"] | null): VerificationEvidence {
  return {
    replayKind,
    interaction: { attemptedClicks: 0, successfulClicks: 0, failedClicks: 0 },
    submittedUrl: "",
    browserVersion: "",
    dialogs: [],
    matchingDialog: null,
    dialogLimitReached: false,
    finalUrls: [],
    pageLimitReached: false,
    navigationError: null,
  };
}

function boundedError(error: unknown, limit: number): string {
  return truncateEvidence(errorMessage(error), Math.min(limit, 4096));
}

function remainingTime(deadline: number): number {
  return Math.max(0, deadline - Date.now());
}
