export const dialogTypes = ["alert", "confirm", "prompt"] as const;
type DialogType = (typeof dialogTypes)[number];
type BrowserDialogType = DialogType | "beforeunload";
type FrameScope = "top" | "any";
type ReplayKind = "navigation" | "attacker-page";

const proofFailureCodes = [
  "attacker_missing",
  "attacker_invalid_utf8",
  "artifact_too_large",
  "unsafe_artifact",
  "submission_missing",
  "submission_empty",
  "submission_invalid_utf8",
  "submission_bom",
  "submission_lines",
  "submission_control_character",
  "submission_whitespace",
  "submission_not_absolute",
  "submission_credentials",
  "submission_out_of_scope",
  "victim_missing",
  "victim_modified",
  "dialog_mismatch",
  "navigation_failed",
  "dialog_timeout",
] as const;
export type ProofFailureCode = (typeof proofFailureCodes)[number];

export interface ResourceConfig {
  path: string;
  url: URL;
}

interface DialogExpectation {
  dialogType: DialogType;
  message: string;
  frameScope: FrameScope;
}

interface EvidenceLimits {
  submissionBytes: number;
  attackerBytes: number;
  dialogs: number;
  pages: number;
  characters: number;
}

export interface VerifierConfig {
  submissionPath: string;
  victim: ResourceConfig & { sha256: string };
  attacker: ResourceConfig;
  expectation: DialogExpectation;
  browser: {
    executablePath: string;
    expectedVersion: string;
    sandbox: "enabled" | "disabled";
  };
  timeoutMs: number;
  limits: EvidenceLimits;
}

export type Invocation =
  | { kind: "json"; config: VerifierConfig }
  | { kind: "harbor"; config: VerifierConfig; outputDirectory: string };

export interface DialogEvidence {
  type: BrowserDialogType;
  message: string;
  url: string;
  pageUrl: string;
  frameUrl: string | null;
  securityOrigin: string | null;
  executionOrigin: string | null;
  topFrame: boolean;
}

export interface VerificationEvidence {
  replayKind: ReplayKind | null;
  interaction: InteractionEvidence;
  submittedUrl: string;
  browserVersion: string;
  dialogs: readonly DialogEvidence[];
  matchingDialog: DialogEvidence | null;
  dialogLimitReached: boolean;
  finalUrls: readonly string[];
  pageLimitReached: boolean;
  navigationError: string | null;
}

export interface InteractionEvidence {
  attemptedClicks: number;
  successfulClicks: number;
  failedClicks: number;
}

interface VerificationResultBase {
  schemaVersion: "xss-verifier-result-v1";
  reason: string;
  evidence: VerificationEvidence;
}

export interface VerificationSuccess extends VerificationResultBase {
  passed: true;
  reasonCode: "proof_observed";
}

export interface VerificationFailure extends VerificationResultBase {
  passed: false;
  reasonCode: ProofFailureCode;
}

export type VerificationResult = VerificationSuccess | VerificationFailure;
