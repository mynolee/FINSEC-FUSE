package com.finsec.fuse.experiments;

import com.finsec.fuse.FuseApplication;
import com.finsec.fuse.common.Json;
import com.finsec.fuse.config.FusePolicy;
import com.finsec.fuse.persistence.Db;
import com.finsec.fuse.policy.*;
import java.sql.DriverManager;
import java.util.*;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.core.env.MapPropertySource;

/** Disposable PostgreSQL schema; no schema DDL ever uses the workflow runtime connection. */
public final class ExperimentSandbox implements AutoCloseable {
    public record Database(String url,String username,String password) {}
    private final Database database;private final String schema;private final ConfigurableApplicationContext context;
    private ExperimentSandbox(Database database,String schema,ConfigurableApplicationContext context){this.database=database;this.schema=schema;this.context=context;}
    public static ExperimentSandbox open(Database database,boolean baseline) {
        if(database.url()==null || !database.url().startsWith("jdbc:postgresql:") || database.username()==null)
            throw new IllegalStateException("A dedicated PostgreSQL experiment database is required");
        String schema="fuse_exp_"+UUID.randomUUID().toString().replace("-","");
        execute(database,"CREATE SCHEMA "+schema);
        try {
            String url=database.url()+(database.url().contains("?")?"&":"?")+"currentSchema="+schema;
            Map<String,Object> properties=new HashMap<>();
            properties.put("spring.datasource.url",url);properties.put("spring.datasource.username",database.username());properties.put("spring.datasource.password",database.password());
            properties.put("spring.datasource.hikari.maximum-pool-size","3");
            properties.put("spring.flyway.user",database.username());properties.put("spring.flyway.password",database.password());
            properties.put("spring.flyway.default-schema",schema);properties.put("spring.flyway.schemas",schema);
            properties.put("spring.flyway.enabled","true");properties.put("fuse.demo-seed","true");
            properties.put("fuse.experiments.enabled","false");properties.put("fuse.worker-enabled","false");
            // Disposable arms never invoke a model. LIVE capture resolves its private input explicitly.
            properties.put("fuse.kyc-mode","replay");
            properties.put("fuse.test-time","2026-10-09T04:00:00Z");properties.put("FUSE_SIGNING_KEY_PATH","");
            properties.put("spring.main.banner-mode","off");properties.put("logging.level.root","ERROR");
            String syntheticServiceToken=com.finsec.fuse.auth.DevActorRegistry.generateToken();
            properties.put("fuse.service-token",syntheticServiceToken);properties.put("FUSE_SERVICE_TOKEN",syntheticServiceToken);
            properties.put("FUSE_REVIEWER_CUSTOMERS","");properties.put("FUSE_SECURITY_CUSTOMERS","");
            // Never import the parent process's bearer credentials into a fresh experiment ledger.
            for(String role:List.of("customer-101","customer-102","customer-103","customer-104","reviewer","security","developer")) {
                String suffix=role.toUpperCase(Locale.ROOT).replace('-','_');
                properties.put("fuse.auth."+role+"-token","");
                properties.put("FUSE_DEV_"+suffix+"_TOKEN","");properties.put("FUSE_"+suffix+"_TOKEN","");
            }
            var context=new SpringApplicationBuilder(FuseApplication.class).profiles("test").web(WebApplicationType.NONE)
                .registerShutdownHook(false).initializers(ctx->{
                    ctx.getEnvironment().getPropertySources().addFirst(new MapPropertySource("isolatedExperiment",properties));
                    if(baseline) {
                        var generic=(GenericApplicationContext)ctx;
                        generic.registerBean("sandboxBaselinePolicy",FusePolicy.class,()-> {
                            FusePolicy policy;
                            try(var stream=new org.springframework.core.io.ClassPathResource("config/demo_policy.json").getInputStream()) {
                                policy=ctx.getBean(Json.class).read(stream.readAllBytes(),FusePolicy.class);
                            }catch(Exception error){throw new IllegalStateException(error);}
                            return new FusePolicy(policy.policyVersion(),1_000_000,policy.kycRisk(),policy.loanRisk(),policy.paymentRisk(),policy.approvalExtraRisk(),1000,
                                policy.grantTtlSeconds(),policy.approvalTtlSeconds(),policy.leaseSeconds(),policy.workerPollMs(),policy.reaperPollMs(),policy.kycTimeoutSeconds(),
                                policy.maxKycConcurrency(),policy.maxAmountKrw(),policy.trustedIssuers(),policy.safeSources(),policy.safeAgentVersions(),policy.allowedEdges());
                        },b->b.setPrimary(true));
                        generic.registerBean("sandboxBaselineQuarantine",QuarantineMatcher.class,
                            ()->new BaselineQuarantineMatcher(ctx.getBean(Db.class)),b->b.setPrimary(true));
                        generic.registerBean("sandboxBaselineEvidence",EvidenceValidator.class,
                            ()->new BaselineEvidenceValidator(ctx.getBean(Db.class),ctx.getBean(FusePolicy.class),ctx.getBean(Json.class)),b->b.setPrimary(true));
                        generic.registerBean("sandboxBaselineDelegation",DelegationService.class,
                            ()->new BaselineDelegationService(ctx.getBean(Db.class),ctx.getBean(Json.class),ctx.getBean(FusePolicy.class),ctx.getBean(GrantCodec.class),
                                ctx.getBean(EnvelopeValidator.class),ctx.getBean(EvidenceValidator.class),ctx.getBean(QuarantineMatcher.class)),b->b.setPrimary(true));
                    }
                }).run();
            try (var owner=DriverManager.getConnection(url,database.username(),database.password())) {
                if(!schema.equals(owner.getSchema()))throw new IllegalStateException("Unexpected experiment fixture schema");
                com.finsec.fuse.auth.DemoTokenAdministration.initialize(owner,
                    context.getBean(com.finsec.fuse.auth.DevActorRegistry.class).configuredBindings());
            } catch(Exception failure) {
                context.close();
                throw new IllegalStateException("Isolated experiment auth fixture initialization failed",failure);
            }
            return new ExperimentSandbox(database,schema,context);
        } catch(RuntimeException error){execute(database,"DROP SCHEMA "+schema+" CASCADE");throw error;}
    }
    public <T>T bean(Class<T> type){return context.getBean(type);}
    public String schema(){return schema;}
    @Override public void close(){try{context.close();}finally{execute(database,"DROP SCHEMA "+schema+" CASCADE");}}
    private static void execute(Database db,String sql){try(var c=DriverManager.getConnection(db.url(),db.username(),db.password());var s=c.createStatement()){s.execute(sql);}catch(Exception error){throw new IllegalStateException("Isolated experiment schema operation failed",error);}}
}
