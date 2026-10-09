export type Row = Record<string, unknown>;
export type WorkflowState =
  | 'KYC_PENDING'
  | 'KYC_VALIDATED'
  | 'REVIEW_READY'
  | 'WAIT_APPROVAL'
  | 'APPROVED'
  | 'PAYMENT_RESERVED'
  | 'PAID'
  | 'REJECTED'
  | 'BLOCKED'
  | 'ON_HOLD';
export interface Workflow extends Row {
  workflowId: string;
  generation: number;
  state: WorkflowState;
  customerId?: string;
  customerAlias?: string;
  businessReference?: string;
  amountKrw?: number;
  payoutAccountId?: string;
  usedRisk: number;
  reservedRisk: number;
  riskLimit: number;
  reasonCodes?: string[];
  lastDecision?: string;
  activeQuarantines?: Array<Row | string>;
  activeJob?: { jobId: string; phase: string; state: string } | null;
  historicalApprovedRiskLimit?: number;
  canApprove?: boolean;
  canResume?: boolean;
}
export interface WorkflowList {
  items: Workflow[];
  total: number;
  page: number;
  size: number;
}
export interface Trace extends Row {
  workflowId: string;
  generation: number;
  runs: Row[];
  results: Row[];
  grants: Row[];
  dependencies: Row[];
  approvals: Row[];
  riskEvents: Row[];
  payments: Row[];
  auditEvents: Row[];
  sourceUses?: Row[];
  evidenceUses?: Row[];
}
export interface ApprovalPreview extends Row {
  workflowId: string;
  generation: number;
  customerId: string;
  amountKrw: number;
  payoutAccountId: string;
  kycResultId: string;
  loanResultId: string;
  evidenceBundleHash: string;
  loanResultHash: string;
  policyVersion: string;
  usedRisk: number;
  reservedRisk: number;
  riskLimitAfterApproval: number;
  reviewSnapshotHash: string;
}
export interface DecisionResponse extends Row {
  requestId: string;
  workflowId?: string;
  generation?: number;
  state: string;
  decision: 'ALLOW' | 'WAIT_APPROVAL' | 'DENY' | 'ERROR';
  reasonCodes: string[];
  message?: string;
  replayed: boolean;
  approvalId?: string;
  quarantineId?: string;
  experimentId?: string;
}
export type QuarantineScope = 'RUN' | 'RESULT' | 'WORKFLOW' | 'SOURCE_VERSION' | 'AGENT_VERSION';
export interface Impact extends Row {
  incidentId: string;
  scope: QuarantineScope;
  target: unknown;
  historicalRunIds: string[];
  currentAffectedWorkflowIds: string[];
  policyHeldWorkflowIds?: string[];
  paidBeforeQuarantine: boolean | unknown[];
  actual: {
    runCount: number;
    roleCount: number;
    workflowCount: number;
    customerCount: number;
    paymentCount: number;
    paidAmountKrw: number;
    atRiskPendingAmountKrw: number;
  };
  potential: {
    roles: string[];
    maxDownstreamDepth: number | null;
    registeredCustomerCount: number | null;
    perApplicationLimitKrw: number | null;
    missingPolicyFields?: string[];
  };
  calculationRefs: unknown;
}
export interface Experiment extends Row {
  experimentId: string;
  status?: string;
  state?: string;
  modelMode?: string;
  syntheticModelOutputs?: boolean;
  liveRobustnessMeasured?: boolean;
  fixtureSetId?: string;
  progress?: number | Row;
  caseOutputs?: Row[];
  results?: Row[];
  metrics?: Row;
  exclusions?: Row[];
}
