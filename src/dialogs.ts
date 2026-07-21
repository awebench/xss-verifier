import type { DialogEvidence, VerifierConfig } from "./types.js";
import { expectedSecurityOrigin, sameDocumentBase } from "./urls.js";

export function dialogMatches(dialog: DialogEvidence, config: VerifierConfig): boolean {
  if (
    dialog.type !== config.expectation.dialogType ||
    dialog.message !== config.expectation.message ||
    (config.expectation.frameScope === "top" && !dialog.topFrame)
  ) {
    return false;
  }

  let dialogUrl: URL;
  let frameUrl: URL;
  try {
    dialogUrl = new URL(dialog.url);
    frameUrl = new URL(dialog.frameUrl ?? "");
  } catch {
    return false;
  }
  if (
    !sameDocumentBase(dialogUrl, config.victim.url) ||
    !sameDocumentBase(frameUrl, config.victim.url)
  ) {
    return false;
  }

  const expectedOrigin = expectedSecurityOrigin(config.victim.url);
  return (
    dialog.securityOrigin === expectedOrigin &&
    (dialog.executionOrigin === null || dialog.executionOrigin === expectedOrigin)
  );
}
