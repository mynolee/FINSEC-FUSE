package com.finsec.fuse.reimplementation.application;

import com.finsec.fuse.reimplementation.persistence.CanonicalJson;
import com.finsec.fuse.reimplementation.persistence.VirtualTransactionalStore;
import com.finsec.fuse.reimplementation.simulation.VirtualExperimentService;
import com.finsec.fuse.reimplementation.simulation.VirtualKycJobAdapter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Finite immutable supplied responses, never a model, network adapter or authority source. */
public final class PreparedSyntheticProviders {
    public record KycEntry(VirtualKycJobAdapter.Delivery delivery, String orderedInputHash,
            Map<String,Object> response) {
        public KycEntry { Objects.requireNonNull(delivery); hash(orderedInputHash); response=CanonicalJson.immutableObject(response); }
        @Override public String toString() { return "PreparedKycEntry[REDACTED]"; }
    }
    public record PairEntry(VirtualExperimentService.Environment environment, String caseId, int repeat,
            String sharedProposalHash, VirtualExperimentService.Observation observation) {
        public PairEntry {
            Objects.requireNonNull(environment); Objects.requireNonNull(observation); hash(sharedProposalHash);
            if(caseId==null||caseId.isBlank()||caseId.length()>160||repeat<1||repeat>10)throw invalid();
        }
        @Override public String toString() { return "PreparedPairEntry[REDACTED]"; }
    }
    private record KycKey(VirtualKycJobAdapter.Delivery delivery,String hash) {}
    private record PairKey(VirtualExperimentService.Environment environment,String caseId,int repeat,String hash) {}
    private final Map<KycKey,Map<String,Object>> kyc;
    private final Map<PairKey,VirtualExperimentService.Observation> pairs;
    public PreparedSyntheticProviders(List<KycEntry> kycEntries,List<PairEntry> pairEntries,
            int maximumKycEntries,int maximumPairArms) {
        if(kycEntries==null||pairEntries==null||maximumKycEntries<1||maximumPairArms<1)throw invalid();
        kycEntries=List.copyOf(kycEntries);pairEntries=List.copyOf(pairEntries);
        if(kycEntries.size()>maximumKycEntries||pairEntries.size()>maximumPairArms)throw invalid();
        var k=new LinkedHashMap<KycKey,Map<String,Object>>();
        for(var entry:kycEntries)if(k.putIfAbsent(new KycKey(entry.delivery(),entry.orderedInputHash()),entry.response())!=null)throw invalid();
        var p=new LinkedHashMap<PairKey,VirtualExperimentService.Observation>();
        for(var entry:pairEntries)if(p.putIfAbsent(new PairKey(entry.environment(),entry.caseId(),entry.repeat(),entry.sharedProposalHash()),entry.observation())!=null)throw invalid();
        kyc=Map.copyOf(k);pairs=Map.copyOf(p);
    }
    public VirtualKycJobAdapter.ProviderPort kyc() {
        return new VirtualKycJobAdapter.ProviderPort() {
            public String mode(){return VirtualTransactionalStore.MODE;}
            public Map<String,Object> evaluate(VirtualKycJobAdapter.Delivery delivery,Map<String,Object> input){
                if(delivery==null||input==null)throw unavailable();
                var found=kyc.get(new KycKey(delivery,CanonicalJson.orderedSha256(input)));
                if(found==null)throw unavailable();return found;
            }
            @Override public String toString(){return "PreparedKycProvider[REDACTED]";}
        };
    }
    public VirtualExperimentService.PairEvaluator pairs() {
        return new VirtualExperimentService.PairEvaluator() {
            public String mode(){return VirtualTransactionalStore.MODE;}
            public VirtualExperimentService.Observation evaluate(VirtualExperimentService.Environment environment,
                    String caseId,int repeat,Map<String,Object> proposal){
                if(environment==null||caseId==null||proposal==null)throw unavailable();
                var found=pairs.get(new PairKey(environment,caseId,repeat,CanonicalJson.sha256(proposal)));
                if(found==null)throw unavailable();return found;
            }
            @Override public String toString(){return "PreparedPairEvaluator[REDACTED]";}
        };
    }
    private static void hash(String value){if(value==null||!value.matches("[0-9a-f]{64}"))throw invalid();}
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("INVALID_SYNTHETIC_PROVIDER_MAPPING");}
    private static IllegalStateException unavailable(){return new IllegalStateException("SYNTHETIC_RESPONSE_UNAVAILABLE");}
    @Override public String toString(){return "PreparedSyntheticProviders[REDACTED]";}
}
