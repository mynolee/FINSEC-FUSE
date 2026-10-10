package com.finsec.fuse.auth;

import com.finsec.fuse.common.ApiErrorHandler;
import com.finsec.fuse.common.Json;
import com.finsec.fuse.testing.DemoTokenTestFixture;
import com.finsec.fuse.config.JsonConfiguration;
import com.finsec.fuse.config.PublicUuidConfiguration;
import com.finsec.fuse.config.PublicUuidBindingAdvice;
import org.springframework.context.annotation.Profile;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.format.support.DefaultFormattingConversionService;
import org.springframework.http.MediaType;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class PublicUuidMvcTest {
    private static final String VALID="fbaedcba-0123-4567-89ab-0123456789ab";
    private static final List<String> INVALID=List.of("1-1-1-1-1","FBAEDCBA-0123-4567-89AB-0123456789AB","AAAAAAAAAAAAAAAAAAAAAA=="," fbaedcba-0123-4567-89ab-0123456789ab","fbaedcba-0123-4567-89ab-0123456789ab ");
    private final BoundaryController controller=new BoundaryController();
    private final String token=DevActorRegistry.generateToken();
    private MockMvc mvc;
    @BeforeEach void setup()throws Exception {
        var configuration=new JsonConfiguration();var json=new Json(configuration.jsonMapper());var policy=configuration.securityPolicy(json.mapper());
        var environment=new MockEnvironment().withProperty("FUSE_DEV_CUSTOMER_101_TOKEN",token);environment.setActiveProfiles("test");
        var conversion=new DefaultFormattingConversionService();new PublicUuidConfiguration().addFormatters(conversion);
        mvc=MockMvcBuilders.standaloneSetup(controller).setConversionService(conversion).setControllerAdvice(new ApiErrorHandler(),new PublicUuidBindingAdvice())
            .addFilters(new PublicHeaderFilter(json,policy,environment),DemoTokenTestFixture.filter(environment,json),new JsonRequestGuard(json,policy)).build();
    }
    @Test void malformedPathUuidsAre400BeforeControllerInvocation()throws Exception {
        for(String id:INVALID)mvc.perform(get("/api/v1/workflows/{id}",id).header("Authorization","Bearer "+token)).andExpect(status().isBadRequest());
        assertEquals(0,controller.calls.get());
        mvc.perform(get("/api/v1/workflows/{id}",VALID).header("Authorization","Bearer "+token)).andExpect(status().isOk());assertEquals(1,controller.calls.get());
    }
    @Test void malformedIdempotencyKeysAre400BeforeControllerInvocation()throws Exception {
        for(String id:INVALID)mvc.perform(post("/api/v1/workflows").header("Authorization","Bearer "+token).header("Idempotency-Key",id).contentType(MediaType.APPLICATION_JSON).content("{}"))
            .andExpect(status().isBadRequest()).andExpect(jsonPath("$.requestId").value(org.hamcrest.Matchers.nullValue()));
        assertEquals(0,controller.calls.get());
        mvc.perform(post("/api/v1/workflows").header("Authorization","Bearer "+token).header("Idempotency-Key",VALID).contentType(MediaType.APPLICATION_JSON).content("{}"))
            .andExpect(status().isOk());assertEquals(1,controller.calls.get());
    }
    @Test void malformedQueryUuidsAre400BeforeControllerInvocation()throws Exception {
        for(String id:INVALID)mvc.perform(get("/api/v1/workflows").queryParam("state",id).header("Authorization","Bearer "+token)).andExpect(status().isBadRequest());
        assertEquals(0,controller.calls.get());
        mvc.perform(get("/api/v1/workflows").queryParam("state",VALID).header("Authorization","Bearer "+token)).andExpect(status().isOk());assertEquals(1,controller.calls.get());
    }
    @Profile("uuid-mvc-contract-test-only")
    @RestController static class BoundaryController {
        final AtomicInteger calls=new AtomicInteger();
        @GetMapping("/api/v1/workflows/{id}") String path(@PathVariable UUID id){calls.incrementAndGet();return "ok";}
        @GetMapping("/api/v1/workflows") String query(@RequestParam("state") UUID id){calls.incrementAndGet();return "ok";}
        @PostMapping("/api/v1/workflows") String header(@RequestHeader("Idempotency-Key") UUID id){calls.incrementAndGet();return "ok";}
    }
}
