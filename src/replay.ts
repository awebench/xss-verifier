import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import puppeteer, { type Browser, type Page } from "puppeteer-core";

import { DialogObserver } from "./browser.js";
import { errorMessage, ProofError, TechnicalError } from "./errors.js";
import { readAttackerPage, readSubmission, readTrustedVictim } from "./files.js";
import { verificationFailure, verificationSuccess } from "./results.js";
import { serveResource, type RunningServer } from "./server.js";
import type {
  AttackerPageConfig,
  NavigationConfig,
  ResourceConfig,
  VerificationEvidence,
  VerificationResult,
  VerifierConfig,
} from "./types.js";
import { truncateEvidence } from "./urls.js";

type ReplayInputs =
  | {
      kind: "navigation";
      victimBytes: Buffer;
      submission: URL;
    }
  | {
      kind: "attacker-page";
      victimBytes: Buffer;
      attackerBytes: Buffer;
      submission: URL;
      attacker: ResourceConfig;
    };

type InteractionResult =
  | { kind: "none" }
  | { kind: "clicked" }
  | { kind: "ambiguous"; count: number }
  | { kind: "failed"; reason: string };

export async function verify(config: VerifierConfig): Promise<VerificationResult> {
  let submittedUrl = "";
  let browserVersion = "";
  let browser: Browser | undefined;
  let observer: DialogObserver | undefined;
  let profile: string | undefined;
  const servers: RunningServer[] = [];

  try {
    let inputs: ReplayInputs;
    try {
      inputs = await loadReplayInputs(config);
    } catch (error) {
      if (error instanceof ProofError) {
        return verificationFailure(error.reasonCode, error.message, emptyEvidence(config));
      }
      throw error;
    }
    submittedUrl = inputs.submission.href;

    servers.push(await serveResource(config.victim.url, inputs.victimBytes));
    if (inputs.kind === "attacker-page") {
      servers.push(await serveResource(inputs.attacker.url, inputs.attackerBytes));
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

    const replay = navigateAndMaybeClick(entryPage, inputs.submission, observer, config);

    const matchingDialog = await observer.waitForMatch(config.timeoutMs);
    const replayResult = await Promise.race([replay, delay(250).then(() => null)]);
    const navigationError = replayResult?.navigationError ?? null;
    const interaction: InteractionResult = replayResult?.interaction ?? { kind: "none" };
    const finalPages = await browser.pages();
    const finalUrls = finalPages
      .slice(0, config.limits.pages)
      .map((page) => truncateEvidence(page.url(), config.limits.characters));
    const evidence: VerificationEvidence = {
      replayKind: config.kind,
      submittedUrl: truncateEvidence(submittedUrl, config.limits.characters),
      browserVersion,
      dialogs: [...observer.dialogs],
      matchingDialog: observer.match,
      dialogLimitReached: observer.dialogLimitReached,
      finalUrls,
      pageLimitReached: finalPages.length > finalUrls.length,
      navigationError,
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
    if (navigationError) {
      return verificationFailure(
        "navigation_failed",
        "the submitted proof URL did not load",
        evidence,
      );
    }
    switch (interaction.kind) {
      case "ambiguous":
        return verificationFailure(
          "button_ambiguous",
          `the submitted page contains ${interaction.count} buttons; expected at most one`,
          evidence,
        );
      case "failed":
        return verificationFailure("button_click_failed", interaction.reason, evidence);
      case "none":
      case "clicked":
        break;
    }
    return verificationFailure(
      "dialog_timeout",
      "no matching browser dialog was observed before timeout",
      evidence,
    );
  } finally {
    observer?.stop();
    await browser?.close().catch(() => {});
    await Promise.allSettled(servers.map(async (server) => server.close()));
    if (profile) await rm(profile, { recursive: true, force: true });
  }
}

async function navigateAndMaybeClick(
  page: Page,
  submission: URL,
  observer: DialogObserver,
  config: VerifierConfig,
): Promise<{ navigationError: string | null; interaction: InteractionResult }> {
  try {
    await page.goto(submission.href, {
      waitUntil: "load",
      timeout: Math.min(15_000, Math.max(1_000, config.timeoutMs)),
    });
  } catch (error) {
    return {
      navigationError: boundedError(error, config.limits.characters),
      interaction: { kind: "none" },
    };
  }

  if (observer.match) {
    return { navigationError: null, interaction: { kind: "none" } };
  }

  try {
    const buttons = await page.$$("button");
    try {
      if (buttons.length > 1) {
        return {
          navigationError: null,
          interaction: { kind: "ambiguous", count: buttons.length },
        };
      }
      if (buttons.length === 0) {
        return { navigationError: null, interaction: { kind: "none" } };
      }
      await buttons[0]!.click();
      return { navigationError: null, interaction: { kind: "clicked" } };
    } finally {
      await Promise.allSettled(buttons.map(async (button) => button.dispose()));
    }
  } catch (error) {
    return {
      navigationError: null,
      interaction: {
        kind: "failed",
        reason: `the page's only button could not be clicked: ${boundedError(
          error,
          config.limits.characters,
        )}`,
      },
    };
  }
}

async function loadReplayInputs(config: VerifierConfig): Promise<ReplayInputs> {
  const victimBytes = await readTrustedVictim(config.victim.path, config.victim.sha256);
  switch (config.kind) {
    case "navigation":
      return loadNavigationInputs(config, victimBytes);
    case "attacker-page":
      return loadAttackerPageInputs(config, victimBytes);
  }
}

async function loadNavigationInputs(
  config: NavigationConfig,
  victimBytes: Buffer,
): Promise<ReplayInputs> {
  const submission = await readSubmission(
    config.submissionPath,
    config.victim.url,
    config.limits.submissionBytes,
  );
  return { kind: "navigation", victimBytes, submission };
}

async function loadAttackerPageInputs(
  config: AttackerPageConfig,
  victimBytes: Buffer,
): Promise<ReplayInputs> {
  const [attackerBytes, submission] = await Promise.all([
    readAttackerPage(config.attacker.path, config.limits.attackerBytes),
    readSubmission(config.submissionPath, config.attacker.url, config.limits.submissionBytes),
  ]);
  return {
    kind: "attacker-page",
    victimBytes,
    attackerBytes,
    submission,
    attacker: config.attacker,
  };
}

function emptyEvidence(config: VerifierConfig): VerificationEvidence {
  return {
    replayKind: config.kind,
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

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
