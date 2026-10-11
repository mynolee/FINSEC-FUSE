package com.finsec.fuse.workflow;

import com.finsec.fuse.common.ApiException;
import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.DemoSeed;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;
import java.io.IOException;
import java.util.*;

/** The immutable, versioned fixture profile is loaded once at startup, never supplied by an AI. */
@Component
public class LoanProfiles {
    private final Map<String,Map<String,Object>> profiles;
    public LoanProfiles(Json json) throws IOException {
        DemoSeed.Fixture fixture;
        try(var stream=new ClassPathResource("fixtures/demo_seed.json").getInputStream()) {
            fixture=json.read(stream.readAllBytes(),DemoSeed.Fixture.class);
        }
        var loaded=new HashMap<String,Map<String,Object>>();
        for(var customer:fixture.customers()) {
            String hash=json.hash(Json.ordered("customerId",customer.customerId(),"monthlyIncomeKrw",customer.monthlyIncomeKrw(),"maxLoanAmountKrw",customer.maxLoanAmountKrw()));
            loaded.put(customer.customerId(),Map.of("customer_id",customer.customerId(),"monthly_income_krw",customer.monthlyIncomeKrw(),
                    "max_loan_amount_krw",customer.maxLoanAmountKrw(),"profile_hash",hash,"policy_version",fixture.loanPolicyVersion()));
        }
        profiles=Map.copyOf(loaded);
    }
    public Map<String,Object> get(String customerId) {
        var profile=profiles.get(customerId);
        if(profile==null)throw new ApiException(409,"APPLICATION_CONFLICT","No registered mock loan profile");
        return profile;
    }
}
