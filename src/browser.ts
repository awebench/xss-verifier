import type { Browser, CDPSession, Protocol } from "puppeteer-core";

import { dialogMatches } from "./dialogs.js";
import { errorMessage, TechnicalError } from "./errors.js";
import type { DialogEvidence, VerifierConfig } from "./types.js";
import { truncateEvidence } from "./urls.js";

interface FrameDetails {
  url: string;
  securityOrigin?: string;
}

interface ExecutionContextDetails {
  contextId: number;
  origin: string;
  owner: CDPSession;
}

interface TargetObservation {
  cdp: CDPSession;
  pageUrl: string;
  targetType: string;
}

export class DialogObserver {
  private readonly capturedDialogs: DialogEvidence[] = [];
  private readonly configuredSessions = new WeakSet<CDPSession>();
  private readonly contexts = new Map<string, ExecutionContextDetails>();
  private readonly frames = new Map<string, FrameDetails>();
  private readonly pending = new Set<Promise<void>>();
  private readonly topFrameIds = new Set<string>();
  private browserCdp: CDPSession | undefined;
  private limitReached = false;
  private matchingDialog: DialogEvidence | undefined;
  private rejectFailure: ((error: TechnicalError) => void) | undefined;
  private resolveMatch: ((dialog: DialogEvidence) => void) | undefined;
  private stopped = false;
  private technicalFailure: TechnicalError | undefined;

  constructor(
    private readonly browser: Browser,
    private readonly config: VerifierConfig,
  ) {}

  get dialogs(): readonly DialogEvidence[] {
    return this.capturedDialogs;
  }

  get dialogLimitReached(): boolean {
    return this.limitReached;
  }

  get match(): DialogEvidence | null {
    return this.matchingDialog ?? null;
  }

  async start(): Promise<void> {
    this.browserCdp = await this.browser.target().createCDPSession();
    await this.configureAutoAttach(this.browserCdp);
    await this.drainPending();
    this.throwIfFailed();
  }

  async waitForMatch(timeoutMs: number): Promise<DialogEvidence | null> {
    this.throwIfFailed();
    if (this.matchingDialog) return this.matchingDialog;

    const match = new Promise<DialogEvidence>((resolve) => {
      this.resolveMatch = resolve;
      if (this.matchingDialog) resolve(this.matchingDialog);
    });
    const failure = new Promise<never>((_resolve, reject) => {
      this.rejectFailure = reject;
      if (this.technicalFailure) reject(this.technicalFailure);
    });
    const timeout = new Promise<null>((resolve) => {
      setTimeout(() => resolve(null), timeoutMs).unref();
    });
    const result = await Promise.race([match, failure, timeout]);
    this.throwIfFailed();
    return result;
  }

  stop(): void {
    this.stopped = true;
    this.resolveMatch = undefined;
    this.rejectFailure = undefined;
  }

  private async configureAutoAttach(cdp: CDPSession): Promise<void> {
    if (this.configuredSessions.has(cdp)) return;
    this.configuredSessions.add(cdp);
    cdp.on("Target.attachedToTarget", (event) => {
      if (this.stopped) return;
      this.queue(this.observeAttachedTarget(cdp, event));
    });
    await cdp.send("Target.setAutoAttach", {
      autoAttach: true,
      waitForDebuggerOnStart: true,
      flatten: true,
    });
  }

  private queue(promise: Promise<void>): void {
    this.pending.add(promise);
    void promise.finally(() => this.pending.delete(promise));
  }

  private async drainPending(): Promise<void> {
    while (this.pending.size > 0) {
      await Promise.allSettled(this.pending);
    }
  }

  private async observeAttachedTarget(
    parent: CDPSession,
    event: Protocol.Target.AttachedToTargetEvent,
  ): Promise<void> {
    const cdp = parent.connection()?.session(event.sessionId);
    if (!cdp) {
      this.fail(new TechnicalError("cannot access an attached browser target"));
      return;
    }
    try {
      if (event.targetInfo.type === "page" || event.targetInfo.type === "iframe") {
        await this.observeSession(cdp, event.targetInfo.url, event.targetInfo.type);
        await this.configureAutoAttach(cdp);
      }
    } catch (error) {
      this.fail(
        new TechnicalError(
          `cannot observe a new browser ${event.targetInfo.type} target: ${errorMessage(error)}`,
          { cause: error },
        ),
      );
    } finally {
      await cdp.send("Runtime.runIfWaitingForDebugger").catch(() => {});
    }
  }

  private async observeSession(
    cdp: CDPSession,
    initialPageUrl: string,
    targetType: string,
  ): Promise<void> {
    const observation: TargetObservation = {
      cdp,
      pageUrl: initialPageUrl,
      targetType,
    };

    cdp.on("Page.frameNavigated", (event) => {
      this.recordFrame(event.frame);
      if (targetType === "page" && !event.frame.parentId) {
        this.topFrameIds.add(event.frame.id);
        observation.pageUrl = event.frame.url;
      }
    });
    cdp.on("Page.frameDetached", (event) => {
      this.frames.delete(event.frameId);
      this.contexts.delete(event.frameId);
      this.topFrameIds.delete(event.frameId);
    });
    cdp.on("Runtime.executionContextCreated", (event) => {
      const frameId = event.context.auxData?.frameId;
      if (frameId && event.context.auxData?.isDefault) {
        this.contexts.set(frameId, {
          contextId: event.context.id,
          origin: event.context.origin,
          owner: cdp,
        });
      }
    });
    cdp.on("Runtime.executionContextDestroyed", (event) => {
      for (const [frameId, context] of this.contexts) {
        if (context.owner === cdp && context.contextId === event.executionContextId) {
          this.contexts.delete(frameId);
        }
      }
    });
    cdp.on("Runtime.executionContextsCleared", () => {
      for (const [frameId, context] of this.contexts) {
        if (context.owner === cdp) this.contexts.delete(frameId);
      }
    });
    cdp.on("Page.javascriptDialogOpening", (event) => {
      void this.captureDialog(observation, event).catch((error: unknown) => {
        this.fail(
          new TechnicalError(`cannot inspect a browser dialog: ${errorMessage(error)}`, {
            cause: error,
          }),
        );
      });
    });

    await Promise.all([cdp.send("Page.enable"), cdp.send("Runtime.enable")]);
    const { frameTree } = await cdp.send("Page.getFrameTree");
    this.collectFrames(frameTree, targetType === "page");
  }

  private async captureDialog(
    observation: TargetObservation,
    event: Protocol.Page.JavascriptDialogOpeningEvent,
  ): Promise<void> {
    const frameId = event.frameId;
    const frame = frameId ? this.frames.get(frameId) : undefined;
    const context = frameId ? this.contexts.get(frameId) : undefined;
    const rawEvidence: DialogEvidence = {
      type: event.type,
      message: event.message,
      url: event.url,
      pageUrl: observation.pageUrl,
      frameUrl: frame?.url ?? event.url,
      securityOrigin: frame?.securityOrigin ?? context?.origin ?? null,
      executionOrigin: context?.origin ?? null,
      topFrame:
        frameId !== undefined &&
        (this.topFrameIds.has(frameId) ||
          (frame === undefined &&
            observation.targetType === "page" &&
            event.url === observation.pageUrl)),
    };
    const matches = dialogMatches(rawEvidence, this.config);
    const evidence = this.truncateDialog(rawEvidence);

    if (this.capturedDialogs.length < this.config.limits.dialogs) {
      this.capturedDialogs.push(evidence);
    } else {
      this.limitReached = true;
    }

    await observation.cdp.send("Page.handleJavaScriptDialog", { accept: false }).catch(() => {});
    if (!this.matchingDialog && matches) {
      this.matchingDialog = evidence;
      this.resolveMatch?.(evidence);
    }
  }

  private truncateDialog(dialog: DialogEvidence): DialogEvidence {
    const limit = this.config.limits.characters;
    return {
      ...dialog,
      message: truncateEvidence(dialog.message, limit),
      url: truncateEvidence(dialog.url, limit),
      pageUrl: truncateEvidence(dialog.pageUrl, limit),
      frameUrl: dialog.frameUrl === null ? null : truncateEvidence(dialog.frameUrl, limit),
    };
  }

  private recordFrame(frame: Protocol.Page.Frame): void {
    this.frames.set(frame.id, {
      url: frame.url,
      ...(frame.securityOrigin === undefined ? {} : { securityOrigin: frame.securityOrigin }),
    });
  }

  private collectFrames(tree: Protocol.Page.FrameTree, topLevelPage: boolean): void {
    const pending: Protocol.Page.FrameTree[] = [tree];
    while (pending.length > 0) {
      const current = pending.pop();
      if (!current) continue;
      this.recordFrame(current.frame);
      if (topLevelPage && !current.frame.parentId) this.topFrameIds.add(current.frame.id);
      for (const child of current.childFrames ?? []) pending.push(child);
    }
  }

  private fail(error: TechnicalError): void {
    if (this.technicalFailure) return;
    this.technicalFailure = error;
    this.rejectFailure?.(error);
  }

  private throwIfFailed(): void {
    if (this.technicalFailure) throw this.technicalFailure;
  }
}
