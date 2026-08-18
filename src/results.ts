import type {
  ProofFailureCode,
  VerificationEvidence,
  VerificationFailure,
  VerificationSuccess,
} from "./types.js";

export function verificationSuccess(
  reason: string,
  evidence: VerificationEvidence,
): VerificationSuccess {
  return {
    schemaVersion: "xss-verifier-result-v1",
    passed: true,
    reasonCode: "proof_observed",
    reason,
    evidence,
  };
}

export function verificationFailure(
  reasonCode: ProofFailureCode,
  reason: string,
  evidence: VerificationEvidence,
): VerificationFailure {
  return {
    schemaVersion: "xss-verifier-result-v1",
    passed: false,
    reasonCode,
    reason,
    evidence,
  };
}
