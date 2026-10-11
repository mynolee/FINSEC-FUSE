package com.finsec.fuse;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class FuseApplication {
    public static void main(String[] args) {
        var application = new SpringApplication(FuseApplication.class);
        // This cannot be disabled by an environment/profile/property flag. Owned internal
        // test/experiment builders are separate trusted entrypoints, not this shipped main.
        application.addInitializers(new com.finsec.fuse.config.RuntimeSchemaAdmission());
        application.run(args);
    }
}
