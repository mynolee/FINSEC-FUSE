package com.finsec.fuse.reimplementation;

/**
 * New implementation of the reviewed LOAN-MOCK-1 product fixture rule.
 * This is a proposal component only; it never grants authority or commits payment.
 */
public final class MockLoanRule {
    private MockLoanRule() {}

    public static boolean recommendsApproval(long monthlyIncomeKrw, long maxLoanAmountKrw,
                                             long amountKrw, boolean ownsActiveAccount) {
        if (!ownsActiveAccount || monthlyIncomeKrw <= 0 || amountKrw <= 0) return false;
        return amountKrw <= maxLoanAmountKrw;
    }
}
