import type { DialogEvidence, VerifierConfig } from "./types.js";
import { expectedSecurityOrigin } from "./urls.js";

export function dialogMatches(dialog: DialogEvidence, config: VerifierConfig): boolean {
  if (
    dialog.type !== config.expectation.dialogType ||
    dialog.message !== config.expectation.message ||
    (config.expectation.frameScope === "top" && !dialog.topFrame)
  ) {
    return false;
  }

  const expectedOrigin = expectedSecurityOrigin(config.victim.url);
  return dialog.executionOrigin === expectedOrigin;
}
