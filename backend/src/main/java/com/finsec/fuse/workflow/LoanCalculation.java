package com.finsec.fuse.workflow;

/** LOAN-MOCK-1 is a deterministic fixture rule, not a real credit or regulatory decision. */
public final class LoanCalculation {
    private LoanCalculation() {}
    public static boolean recommendsApproval(long monthlyIncomeKrw, long maxLoanAmountKrw,
                                             long amountKrw, boolean ownsActiveAccount) {
        return monthlyIncomeKrw > 0 && amountKrw > 0 && amountKrw <= maxLoanAmountKrw && ownsActiveAccount;
    }
}
