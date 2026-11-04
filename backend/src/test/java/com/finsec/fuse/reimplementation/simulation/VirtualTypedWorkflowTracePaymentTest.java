package com.finsec.fuse.reimplementation.simulation;

import com.finsec.fuse.reimplementation.auth.SyntheticMockPaymentReceiptCodec;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantReplayAssessment.CommandIdentity;
import com.finsec.fuse.reimplementation.auth.SyntheticGrantTemporalAssessment;
import com.finsec.fuse.reimplementation.grant.*;
import com.finsec.fuse.reimplementation.persistence.ActionJournal;
import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import java.util.*;
import org.junit.jupiter.api.Test;
import static com.finsec.fuse.reimplementation.grant.OwnedGrantTransactionPort.*;
import static com.finsec.fuse.reimplementation.grant.SyntheticMockPaymentTransactionBinding.*;
import static com.finsec.fuse.reimplementation.simulation.VirtualGrantContinuationFixture.id;
import static org.junit.jupiter.api.Assertions.*;

/** Committed mock-payment metadata comes from real virtual service receipts, never a reservation label. */
final class VirtualTypedWorkflowTracePaymentTest {
    private static final String PAYMENTS="virtual_grant_profile_payments",LOCAL="virtual_grant_profile_receipts",
            PLAN_RECEIPTS="virtual_grant_profile_plan_receipts",APPROVALS="virtual_grant_profile_review_approvals";
    private static final Set<String> PAYMENT_FIELDS=Set.of("paymentId","approvalId","reservationId","grantId","runId",
            "workflowId","generation","amountKrw","reservationState","approvalState","profileName","profileVersion","receiptDigest");
    private static final Set<String> RISK_FIELDS=Set.of("riskEventId","workflowId","generation","eventType","stage","points","runId","policyVersion");
    static final class Fixture {
        // Frozen supported composition; this file adds only payment completion and trace assertions.
        final VirtualTypedWorkflowReadReservedScopeTest.Scenario reserved=new VirtualTypedWorkflowReadReservedScopeTest.Scenario();
        final PaymentCommand command;
        final SyntheticMockPaymentTransactionService payments;
        final String reserveRequestId;
        final Map<String,Object> reserveOrigin;
        Fixture(){
            var d=reserved.reserved;var prior=reserved.loanConsumption.identity();
            var identity=new CommandIdentity(reserved.f.context.actorId(),id(8307),"synthetic-payment-complete",
                    prior.canonicalizationVersion(),prior.canonicalBodyDigest(),d.grantId(),d.actionId(),d.targetRunId(),
                    d.workflowId(),d.generation(),d.customerId());
            var digest=new DigestBinding(identity.canonicalBodyDigest(),"SHA-256",new byte[]{1,2,3});
            var input=new SyntheticMockPaymentReceiptCodec.Input(identity.globalRequestId(),identity.actorId(),identity.operation(),
                    identity.canonicalizationVersion(),digest.algorithm(),digest.bytes(),d.grantId(),d.actionId(),d.paymentId(),d.targetRunId(),
                    d.approvalId(),d.reservationId(),d.workflowId(),d.generation(),d.customerId(),d.applicationId(),d.amountKrw(),
                    d.payoutAccountId(),d.securityPolicyVersion(),"EXECUTE_MOCK_PAYMENT","COMMITTED","CONSUMED");
            command=new PaymentCommand(new StageCommand(identity,reserved.payment.action()),digest,input);
            payments=new SyntheticMockPaymentTransactionService(reserved.f.journal,new PaymentFactResolver(){
                public Gate current(ServerContext actor,PaymentCommand value,OwnedTx tx){
                    if(!actor.actorId().equals(identity.actorId())||!command.equals(value)||value.stage().identity().generation()!=2)
                        return Gate.UNKNOWN;
                    var c=reserved.f.firstCommand().newRoot().claims();
                    var time=new SyntheticGrantTemporalAssessment.TemporalFacts(reserved.now.getEpochSecond(),c.issuedAt(),c.expiresAt(),
                            SyntheticGrantTemporalAssessment.ChainPosition.ROOT,null);
                    return SyntheticGrantTemporalAssessment.assess(time,reserved.f.seed.facts.rev()).blockers().isEmpty()?Gate.CLEAR:Gate.UNKNOWN;
                }
                public ResolvedPayment resolve(ServerContext actor,PaymentCommand value,OwnedTx tx){
                    assertEquals(command,value);assertEquals(d,tx.paymentDomain(d.reservationId()));
                    return new ResolvedPayment(d,digest,input,List.of());
                }
            });
            var origins=reserved.store.snapshot().get(PLAN_RECEIPTS).entrySet().stream()
                    .filter(e->"RESERVE".equals(e.getValue().get("purpose")))
                    .filter(e->((Map<?,?>)e.getValue().get("domain")).get("reservationId").equals(d.reservationId().toString())).toList();
            assertEquals(1,origins.size());reserveRequestId=origins.get(0).getKey();reserveOrigin=origins.get(0).getValue();
            assertEquals(reserved.f.terms.payPoints(),reserveOrigin.get("riskPoints"));
            assertNotNull(reserved.store.snapshot().get(ActionJournal.TABLE).get(reserveRequestId).get("reply"));
        }
        Receipt complete(){
            var outcome=payments.completePayment(reserved.f.context,command);
            assertEquals(Status.VIRTUAL_COMMITTED_IN_PROCESS,outcome.status());assertNotNull(outcome.receipt());
            assertEquals(ReceiptKind.CONSUMPTION,outcome.receipt().kind());
            assertFalse(outcome.actualAuthority());assertFalse(outcome.durable());return outcome.receipt();
        }
        Map<String,Object> trace(){
            var before=reserved.store.snapshot();int writes=reserved.store.puts;
            var result=reserved.reader().trace(SimulationFixture.ACTOR,id(1));
            assertEquals(Boolean.FALSE,result.get("cryptographicAuthorityImplemented"));
            assertEquals(reserved.store.mode(),result.get("executionMode"));
            assertEquals(writes,reserved.store.puts);assertEquals(before,reserved.store.snapshot());return result;
        }
    }
    @SuppressWarnings("unchecked") private static List<Map<String,Object>> rows(Map<String,Object> trace,String key){
        assertInstanceOf(List.class,trace.get(key));var list=(List<?>)trace.get(key);
        for(var item:list)assertInstanceOf(Map.class,item);
        return (List<Map<String,Object>>)(List<?>)list;
    }
    private static Map<String,Object> onlyPayment(Fixture f,Map<String,Object> trace){
        var rows=rows(trace,"payments");assertEquals(1,rows.size());var row=rows.get(0);var d=f.reserved.reserved;
        assertEquals(PAYMENT_FIELDS,row.keySet());
        assertEquals(d.paymentId().toString(),row.get("paymentId"));assertEquals(d.approvalId().toString(),row.get("approvalId"));
        assertEquals(d.reservationId().toString(),row.get("reservationId"));assertEquals(d.grantId().toString(),row.get("grantId"));
        assertEquals(d.targetRunId().toString(),row.get("runId"));assertEquals(d.workflowId().toString(),row.get("workflowId"));
        assertEquals(d.generation(),row.get("generation"));assertEquals(d.amountKrw(),row.get("amountKrw"));
        assertEquals("COMMITTED",row.get("reservationState"));assertEquals("CONSUMED",row.get("approvalState"));
        assertEquals(SyntheticMockPaymentReceiptCodec.PROFILE_NAME,row.get("profileName"));
        assertEquals(SyntheticMockPaymentReceiptCodec.PROFILE_VERSION,row.get("profileVersion"));
        assertInstanceOf(String.class,row.get("receiptDigest"));assertTrue(((String)row.get("receiptDigest")).matches("[0-9a-f]{64}"));
        var stored=f.reserved.store.snapshot().get(PAYMENTS).get(d.paymentId().toString());
        assertNotNull(stored);assertEquals(stored.get("receiptDigest"),row.get("receiptDigest"));return row;
    }
    private static Map<String,Object> risk(Map<String,Object> trace,String type,String source){
        var found=rows(trace,"riskEvents").stream().filter(r->type.equals(r.get("eventType"))&&source.equals(r.get("riskEventId"))).toList();
        assertEquals(1,found.size());var row=found.get(0);assertEquals(RISK_FIELDS,row.keySet());
        assertEquals("PAYMENT",row.get("stage"));return row;
    }
    @Test void anActuallyReservedPlanIsNotProjectedAsACommittedPayment(){
        var f=new Fixture();var d=f.reserved.reserved;var trace=f.trace();
        assertTrue(rows(trace,"payments").isEmpty());
        assertFalse(f.reserved.store.snapshot().getOrDefault(PAYMENTS,Map.of()).containsKey(d.paymentId().toString()));
        assertEquals("RESERVED",f.reserved.store.snapshot().get("virtual_grant_profile_payment_plans").get(d.reservationId().toString()).get("reservationState"));
        assertEquals("RESERVED",f.reserved.store.snapshot().get(APPROVALS).get(d.approvalId().toString()).get("state"));
        assertTrue(rows(trace,"riskEvents").stream().noneMatch(r->"CONSUME".equals(r.get("eventType"))&&"PAYMENT".equals(r.get("stage"))));
    }
    @Test void actualMockPaymentCompletionProjectsExactCommittedDomainAndConsumedApproval(){
        var f=new Fixture();assertTrue(rows(f.trace(),"payments").isEmpty());var receipt=f.complete();var d=f.reserved.reserved;
        assertEquals(d.paymentId(),receipt.result().resultId());
        assertEquals("CONSUMED",f.reserved.store.snapshot().get(APPROVALS).get(d.approvalId().toString()).get("state"));
        assertEquals("COMMITTED",f.reserved.store.snapshot().get("virtual_grant_profile_payment_plans").get(d.reservationId().toString()).get("reservationState"));
        onlyPayment(f,f.trace());
    }
    @Test void paymentTraceWhitelistsMetadataWithoutRawReceiptInputOrInventedTime(){
        var f=new Fixture();f.complete();var row=onlyPayment(f,f.trace());
        for(String key:List.of("input","canonicalBytes","canonicalBodyDigest","bindingBytes","actorId","authenticatedActor",
                "operation","customerId","applicationId","payoutAccountId","paidAt","createdAt","outcome"))assertFalse(row.containsKey(key));
        var encoded=CanonicalJson.write(row);
        assertFalse(encoded.contains(f.reserved.f.context.actorId()));
        assertFalse(encoded.contains(f.reserved.f.newApplication.source().text()));
        assertFalse(encoded.contains(f.reserved.reserved.payoutAccountId().toString()));
    }
    @Test void reserveAndConsumeRiskEventsHaveDifferentActualImmutableReceiptSources(){
        var f=new Fixture();var original=f.reserveOrigin;var before=f.trace();
        var reserve=risk(before,"RESERVE",f.reserveRequestId);
        assertEquals(original.get("riskPoints"),reserve.get("points"));
        f.complete();var request=f.command.stage().identity().globalRequestId().toString();assertNotEquals(f.reserveRequestId,request);
        var snapshot=f.reserved.store.snapshot();assertEquals(original,snapshot.get(PLAN_RECEIPTS).get(f.reserveRequestId));
        var local=snapshot.get(LOCAL).get(request);assertNotNull(local);assertEquals("CONSUMPTION",local.get("kind"));
        assertNotNull(snapshot.get(ActionJournal.TABLE).get(request).get("reply"));
        var after=f.trace();var retained=risk(after,"RESERVE",f.reserveRequestId);var consume=risk(after,"CONSUME",request);
        assertEquals(reserve,retained);assertEquals(original.get("riskPoints"),consume.get("points"));
        for(var row:List.of(retained,consume)){
            assertEquals(f.reserved.reserved.workflowId().toString(),row.get("workflowId"));assertEquals(2,row.get("generation"));
            assertEquals(f.reserved.reserved.targetRunId().toString(),row.get("runId"));
            assertEquals(f.reserved.f.terms.policyVersion(),row.get("policyVersion"));
            assertFalse(row.containsKey("createdAt"));assertFalse(row.containsKey("occurredAt"));
        }
    }
}
