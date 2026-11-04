package com.finsec.fuse.reimplementation.application;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import jakarta.servlet.ServletException;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletResponse;

class VirtualRequestAdmissionValveTest {
    private static Response response(MockHttpServletResponse facade) {
        Response response = mock(Response.class);
        when(response.getResponse()).thenReturn(facade);
        doAnswer(call -> { facade.setHeader(call.getArgument(0), call.getArgument(1)); return null; })
                .when(response).setHeader(anyString(), anyString());
        return response;
    }

    @Test void closedOrUnavailableGateDoesNotDispatch() throws Exception {
        for (boolean throwing : new boolean[] {false, true}) {
            AtomicInteger calls = new AtomicInteger();
            VirtualRequestAdmissionValve valve = new VirtualRequestAdmissionValve(1, () -> {
                if (throwing) throw new IllegalStateException("synthetic-private");
                return false;
            });
            valve.setNext(new ValveBase(false) {
                @Override public void invoke(Request request, Response response) { calls.incrementAndGet(); }
            });
            MockHttpServletResponse facade = new MockHttpServletResponse();
            valve.invoke(null, response(facade));
            assertEquals(0, calls.get()); assertEquals(503, facade.getStatus());
            assertEquals("no-store", facade.getHeader("Cache-Control"));
            assertEquals("VIRTUAL_SIMULATION", facade.getHeader("X-Fuse-Execution-Mode"));
            assertFalse(facade.getContentAsString().contains("synthetic-private"));
        }
    }

    @Test void saturationRejectsNestedDispatchAndReleasesOnlyOwnedPermit() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        VirtualRequestAdmissionValve valve = new VirtualRequestAdmissionValve(1, () -> true);
        MockHttpServletResponse nested = new MockHttpServletResponse();
        valve.setNext(new ValveBase(false) {
            @Override public void invoke(Request request, Response response) throws IOException, ServletException {
                if (calls.incrementAndGet() == 1) valve.invoke(null, response(nested));
            }
        });
        valve.invoke(null, response(new MockHttpServletResponse()));
        assertEquals(1, calls.get()); assertEquals(503, nested.getStatus());
        valve.invoke(null, response(new MockHttpServletResponse()));
        assertEquals(2, calls.get());
    }

    @Test void downstreamFailureReleasesPermitWithoutRetry() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        VirtualRequestAdmissionValve valve = new VirtualRequestAdmissionValve(1, () -> true);
        valve.setNext(new ValveBase(false) {
            @Override public void invoke(Request request, Response response) throws ServletException {
                if (calls.incrementAndGet() == 1) throw new ServletException("synthetic-failure");
            }
        });
        assertThrows(ServletException.class, () -> valve.invoke(null, response(new MockHttpServletResponse())));
        assertEquals(1, calls.get());
        valve.invoke(null, response(new MockHttpServletResponse())); assertEquals(2, calls.get());
    }

    @Test void gateClosingAfterAcquisitionRejectsAndReleasesPermit() throws Exception {
        AtomicInteger reads = new AtomicInteger(); AtomicInteger dispatched = new AtomicInteger();
        AtomicBoolean stable = new AtomicBoolean(false);
        VirtualRequestAdmissionValve valve = new VirtualRequestAdmissionValve(1,
                () -> stable.get() || reads.incrementAndGet() == 1);
        valve.setNext(new ValveBase(false) {
            @Override public void invoke(Request request, Response response) { dispatched.incrementAndGet(); }
        });
        MockHttpServletResponse facade = new MockHttpServletResponse(); valve.invoke(null, response(facade));
        assertEquals(503, facade.getStatus()); assertEquals(0, dispatched.get());
        stable.set(true); valve.invoke(null, response(new MockHttpServletResponse()));
        assertEquals(1, dispatched.get());
        assertThrows(IllegalArgumentException.class, () -> new VirtualRequestAdmissionValve(0, () -> true));
    }
}
