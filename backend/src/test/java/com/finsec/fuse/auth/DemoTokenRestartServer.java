package com.finsec.fuse.auth;

import com.finsec.fuse.FuseApplication;
import java.net.URI;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import org.springframework.boot.SpringApplication;

/** Test-only child JVM. Private config is its only argument; no auth controls or provisioning. */
public final class DemoTokenRestartServer {
    public static void main(String[] args)throws Exception {
        if(args.length!=1)throw new IllegalArgumentException("Expected private test configuration");
        Properties config=new Properties();try(var input=Files.newInputStream(Path.of(args[0]))){config.load(input);}
        URI database=URI.create(config.getProperty("database").substring(5));
        if(!"postgresql".equals(database.getScheme())||!Set.of("localhost","127.0.0.1","[::1]").contains(database.getHost()))throw new IllegalArgumentException("Owned loopback database required");
        Map<String,Object> properties=new HashMap<>();
        properties.put("spring.profiles.active","test");properties.put("server.address","127.0.0.1");properties.put("server.port","0");
        properties.put("spring.datasource.url",config.getProperty("database"));properties.put("spring.datasource.username","postgres");properties.put("spring.datasource.password","");
        properties.put("spring.flyway.enabled","false");properties.put("fuse.demo-seed","true");properties.put("fuse.worker-enabled","false");properties.put("fuse.experiments.enabled","false");
        properties.put("fuse.kyc-mode","replay");properties.put("fuse.kyc-base-url","http://127.0.0.1:9");
        properties.put("fuse.service-token",config.getProperty("service"));properties.put("fuse.auth.reviewer-token",config.getProperty("reviewer"));
        properties.put("FUSE_SIGNING_KEY_ID",config.getProperty("keyId"));properties.put("fuse.signing-key-path","");
        properties.put("fuse.test-time",config.getProperty("workflowTime"));
        var application=new SpringApplication(FuseApplication.class);application.setAdditionalProfiles("test");
        application.addInitializers(context->context.getEnvironment().getPropertySources().addFirst(new org.springframework.core.env.MapPropertySource("ownedRestartFixture",properties)));
        try(var context=application.run()) {
            Path port=Path.of(config.getProperty("portFile"));Path temporary=port.resolveSibling(port.getFileName()+".tmp");
            Files.writeString(temporary,context.getEnvironment().getRequiredProperty("local.server.port"),StandardOpenOption.CREATE_NEW);
            Files.move(temporary,port,StandardCopyOption.ATOMIC_MOVE);
            long deadline=System.nanoTime()+Duration.ofMinutes(3).toNanos();Path stop=Path.of(config.getProperty("stopFile"));
            while(!Files.exists(stop)) {if(System.nanoTime()>deadline)throw new IllegalStateException("Owned test rendezvous expired");Thread.sleep(25);}
        }
    }
}
