package com.finsec.fuse.reimplementation;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class MockLoanRuleTest {
    @Test void acceptsOnlyPositiveIncomePositiveAmountAndAnOwnedActiveAccount() {
        assertTrue(MockLoanRule.recommendsApproval(1, 10, 10, true));
        assertFalse(MockLoanRule.recommendsApproval(0, 10, 1, true));
        assertFalse(MockLoanRule.recommendsApproval(-1, 10, 1, true));
        assertFalse(MockLoanRule.recommendsApproval(1, 10, 0, true));
        assertFalse(MockLoanRule.recommendsApproval(1, 10, -1, true));
        assertFalse(MockLoanRule.recommendsApproval(1, 10, 1, false));
    }

    @Test void enforcesTheMaximumWithoutMultiplicationOrOverflow() {
        assertFalse(MockLoanRule.recommendsApproval(1, 10, 11, true));
        assertFalse(MockLoanRule.recommendsApproval(1, -1, 1, true));
        assertTrue(MockLoanRule.recommendsApproval(Long.MAX_VALUE, Long.MAX_VALUE, Long.MAX_VALUE, true));
    }
}
