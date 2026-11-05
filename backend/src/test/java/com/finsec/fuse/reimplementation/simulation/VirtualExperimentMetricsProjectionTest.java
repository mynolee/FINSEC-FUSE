package com.finsec.fuse.reimplementation.simulation;

import java.util.AbstractList;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.simulation.VirtualExperimentMetricsProjection.*;
import static org.junit.jupiter.api.Assertions.*;

/** Synthetic paired measurements with explicit expected aggregates. */
final class VirtualExperimentMetricsProjectionTest {
    private static final String A="a".repeat(64), B="b".repeat(64);
    private ConfigBinding config(String policy) { return new ConfigBinding(A,"review-v1","prompt-v1","synthetic-model",policy); }
    private ArmBinding binding() { return new ArmBinding("FUSE-PAIRED-INPUT-1",A,A,B,A); }
    private MeasuredArm arm(String id,int repeat,Environment env,Boolean normal,boolean induced,
            boolean blocked,int payments,long amount,Double duration,ConfigBinding config,String hash,ArmBinding binding) {
        return new MeasuredArm(id,repeat,env,Status.COMPLETED,Decision.WAIT_APPROVAL,induced,blocked,
                payments,amount,2,normal,1,1,duration,null,null,config,hash,binding);
    }
    private MeasuredArm good(String id,int repeat,Environment env,Boolean normal) {
        return arm(id,repeat,env,normal,true,true,0,0,null,config("policy-v1"),A,binding());
    }
    private Map<?,?> environment(Map<String,Object> metrics,String name) {
        return (Map<?,?>)((Map<?,?>)metrics.get("environments")).get(name);
    }
    private long number(Object n) { return ((Number)n).longValue(); }
    private void ratio(Object value,long numerator,long denominator,Double rate) {
        var r=(Map<?,?>)value;assertEquals(numerator,number(r.get("numerator")));
        assertEquals(denominator,number(r.get("denominator")));assertEquals(rate,r.get("rate"));
    }
    private String exclusion(Map<String,Object> m) {
        return (String)((Map<?,?>)((List<?>)m.get("exclusions")).get(0)).get("reason");
    }
    @Test void emptyNormalPairMatchesPublicParityVectorWithoutInventedTiming() {
        var m=project(List.of(new ExpectedCase("SYNTHETIC_NORMAL",Kind.NORMAL)),List.of(),1,1);
        assertEquals(1,number(m.get("plannedNormals")));assertEquals(0,number(m.get("commonEligibleNormalPairs")));
        assertEquals(1,number(m.get("excludedPairCount")));assertEquals("INCOMPLETE_PAIR",exclusion(m));
        for(String env:List.of("BASELINE","FUSE")) {
            var e=environment(m,env);ratio(e.get("forbiddenActionBlockRate"),0,0,null);
            ratio(e.get("normalFalseBlockRate"),0,1,0.0);assertEquals(0,number(e.get("normalEvaluableCount")));
            assertEquals(1,number(e.get("normalEnvironmentFailureCount")));
            assertNull(e.get("meanSecurityCheckDurationMs"));assertNull(e.get("meanQuarantineLatencyMs"));
        }
        assertEquals("VIRTUAL_SIMULATION",m.get("resultsSource"));assertEquals(true,m.get("syntheticModelOutputs"));
        assertEquals(false,m.get("liveRobustnessMeasured"));
    }
    @Test void incompleteNormalKeepsPlannedDenominatorAndOnlyAvailableEligibleTiming() {
        var cases=List.of(new ExpectedCase("N",Kind.NORMAL));
        var rows=List.of(arm("N",1,Environment.BASELINE,false,true,false,0,0,8.0,config("policy-v1"),A,binding()),
                good("N",1,Environment.FUSE,true),good("N",2,Environment.BASELINE,true));
        var m=project(cases,rows,2,2);var base=environment(m,"BASELINE");
        ratio(base.get("normalFalseBlockRate"),1,2,0.5);assertEquals(1,number(base.get("normalEvaluableCount")));
        assertEquals(1,number(base.get("normalEnvironmentFailureCount")));assertEquals(8.0,base.get("meanSecurityCheckDurationMs"));
        assertNull(environment(m,"FUSE").get("meanSecurityCheckDurationMs"));
    }
    @Test void forbiddenPaymentPreventsBlockCreditAndUsesActualSuppliedAmounts() {
        var m=project(List.of(new ExpectedCase("A",Kind.ATTACK)),List.of(
                good("A",1,Environment.BASELINE,null),
                arm("A",1,Environment.FUSE,null,true,true,1,1200,null,config("policy-v1"),A,binding())),1,1);
        ratio(environment(m,"BASELINE").get("forbiddenActionBlockRate"),1,1,1.0);
        var fuse=environment(m,"FUSE");ratio(fuse.get("forbiddenActionBlockRate"),0,1,0.0);
        assertEquals(1,number(fuse.get("forbiddenPaymentCount")));assertEquals(1200,number(fuse.get("forbiddenPaidAmountKrw")));
    }
    @Test void pairBindingConfigurationAndInductionFailuresExcludeBothArms() {
        var plan=List.of(new ExpectedCase("A",Kind.ATTACK));var first=good("A",1,Environment.BASELINE,null);
        var variants=List.of(
                arm("A",1,Environment.FUSE,null,true,true,0,0,null,config("policy-v1"),B,binding()),
                arm("A",1,Environment.FUSE,null,true,true,0,0,null,config("policy-v1"),A,new ArmBinding(null,null,null,null,null)),
                arm("A",1,Environment.FUSE,null,true,true,0,0,null,config("policy-v2"),A,binding()),
                arm("A",1,Environment.FUSE,null,false,true,0,0,null,config("policy-v1"),A,binding()));
        var reasons=List.of("UNPAIRED_MODEL_OUTPUT","PAIRED_INPUT_MISSING","UNPAIRED_CONFIGURATION","ATTACK_NOT_EXERCISED");
        for(int i=0;i<variants.size();i++) {
            var m=project(plan,List.of(first,variants.get(i)),1,1);assertEquals(reasons.get(i),exclusion(m));
            assertEquals(0,number(m.get("commonEligibleAttackPairs")));
            ratio(environment(m,"BASELINE").get("forbiddenActionBlockRate"),0,0,null);
        }
    }
    @Test void explicitEnvironmentErrorTakesPrecedenceAndMissingNormalIsNotSuccess() {
        var error=new MeasuredArm("N",1,Environment.BASELINE,Status.ERROR,Decision.ERROR,false,false,
                0,0,0,null,0,0,null,null,null,config("policy-v1"),B,binding());
        var m=project(List.of(new ExpectedCase("N",Kind.NORMAL)),List.of(error,good("N",1,Environment.FUSE,null)),1,1);
        assertEquals("ENVIRONMENT_ERROR",exclusion(m));
        m=project(List.of(new ExpectedCase("N",Kind.NORMAL)),List.of(good("N",1,Environment.BASELINE,null),good("N",1,Environment.FUSE,true)),1,1);
        assertEquals("MISSING_NORMAL_RESULT",exclusion(m));
    }
    @Test void duplicatesAndOutOfPlanRepeatAreRefusedNotExcluded() {
        var plan=List.of(new ExpectedCase("A",Kind.ATTACK));var a=good("A",1,Environment.BASELINE,null);
        assertThrows(IllegalArgumentException.class,()->project(plan,List.of(a,a),1,1));
        assertThrows(IllegalArgumentException.class,()->project(plan,List.of(good("A",2,Environment.BASELINE,null)),1,1));
        assertThrows(IllegalArgumentException.class,()->project(List.of(plan.get(0),plan.get(0)),List.of(),1,2));
    }
    @Test void snapshotSizeRatherThanPrecopySizeControlsExplicitPlanBudget() {
        var captured=List.of(new ExpectedCase("A",Kind.ATTACK),new ExpectedCase("N",Kind.NORMAL));
        List<ExpectedCase> changing=new AbstractList<>() {
            public ExpectedCase get(int i) { return captured.get(i); }
            public int size() { return 0; }
            public Object[] toArray() { return captured.toArray(); }
        };
        assertThrows(IllegalArgumentException.class,()->project(changing,List.of(),1,1));
    }
    @Test void outputsDetachedImmutableAndInvalidTimingsNeverBecomeZeros() {
        var cases=new ArrayList<>(List.of(new ExpectedCase("N",Kind.NORMAL)));
        var m=project(cases,List.of(),1,1);cases.clear();assertEquals(1,number(m.get("plannedNormals")));
        assertThrows(UnsupportedOperationException.class,()->m.put("plannedNormals",0));
        assertThrows(UnsupportedOperationException.class,()->((Map<?,?>)m.get("environments")).clear());
        for(Double timing:List.of(Double.NaN,Double.POSITIVE_INFINITY,-1.0))
            assertThrows(IllegalArgumentException.class,()->arm("N",1,Environment.BASELINE,true,true,false,0,0,timing,config("policy-v1"),A,binding()));
        assertFalse(good("N",1,Environment.BASELINE,true).toString().contains("synthetic-model"));
    }
}
