// Public diagnostics may contain only these fixed, source-reviewed labels.
export const PHASES = [
  'SESSION_NAVIGATE',
  'SESSION_DISCONNECT',
  'SESSION_LOGIN_FORM',
  'SESSION_TOKEN_INPUT',
  'SESSION_CONNECT',
  'SESSION_CONNECTED',
  'WORKFLOW_WAIT_STATE',
  'WORKFLOW_STATE_VERIFIED',
  'WORKFLOW_OPEN_CREATE',
  'WORKFLOW_SELECT_FIXTURE',
  'WORKFLOW_SUBMIT',
  'WORKFLOW_RESPONSE',
  'WORKFLOW_DETAIL_ROUTE',
  'COMMAND_CLICK',
  'COMMAND_RESPONSE',
  'COMMAND_ACCEPTED',
  'APPROVAL_OPEN',
  'APPROVAL_VERIFY_PREVIEW',
  'APPROVAL_CONFIRM',
  'APPROVAL_LEDGER',
  'MISSING_EVIDENCE_CHECK',
  'QUARANTINE_OPEN',
  'QUARANTINE_FILL',
  'QUARANTINE_IMPACT',
  'QUARANTINE_RELEASE',
  'QUARANTINE_RELEASE_VERIFY',
  'RECOVERY_OPEN',
  'RECOVERY_VERIFY_HISTORY',
  'REPLAY_OPEN',
  'REPLAY_CONFIGURE',
  'REPLAY_WAIT_COMPLETE',
  'REPLAY_VERIFY_ROWS',
  'REPLAY_REFRESH',
  'REPLAY_JSON_EXPORT',
  'REPLAY_JSON_COMPARE',
  'REPLAY_CSV_EXPORT',
  'REPLAY_CSV_COMPARE',
  'SECURITY_ROUTE_STUB',
  'SECURITY_LITERAL_LINK',
  'SECURITY_NO_EXECUTION',
  'SECURITY_LOGOUT_HISTORY',
  'SECURITY_HEADERS',
  'SECURITY_CSP',
  'SECURITY_FRAME_TOP_LEVEL',
  'SECURITY_FRAME_PARENT',
  'SECURITY_FRAME_DENIAL',
  'SECURITY_FRAME_UI_ABSENT',
] as const;
export type Phase = (typeof PHASES)[number];
export const PHASE_ANNOTATION = 'fuse-checkpoint';
export const MAX_CHECKPOINTS = 64;

type FrameAncestorIssue = {
  blockedURL?: string;
  violatedDirective?: string;
  isReportOnly?: boolean;
  contentSecurityPolicyViolationType?: string;
  frameAncestor?: { frameId?: string };
};

/** Reduce the correlated Chromium policy issue to a boolean; never return browser diagnostics. */
export function isEnforcedFrameAncestorDenial(
  details: FrameAncestorIssue | undefined,
  protectedOrigin: string,
  parentFrameId: string,
): boolean {
  if (
    !details ||
    details.isReportOnly !== false ||
    details.contentSecurityPolicyViolationType !== 'kURLViolation' ||
    !/^frame-ancestors(?:\s|$)/.test(details.violatedDirective ?? '') ||
    !parentFrameId ||
    details.frameAncestor?.frameId !== parentFrameId
  )
    return false;
  // Chromium strips the protected URL to its origin for frame-ancestors, and identifies the
  // disallowed ancestor separately. Never normalize away a supplied path, query or credential.
  try {
    const origin = new URL(protectedOrigin);
    return (
      ['http:', 'https:'].includes(origin.protocol) &&
      origin.origin === protectedOrigin &&
      details.blockedURL === origin.href
    );
  } catch {
    return false;
  }
}
