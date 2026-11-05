package com.finsec.fuse.reimplementation.http;

import jakarta.servlet.AsyncContext;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashSet;

/** Immutable, repeatable, bounded UTF-8 body for the synchronous JSON controller contract. */
public final class CachedBodyRequest extends HttpServletRequestWrapper {
    private final byte[] body;
    private final boolean originalTransferEncodingPresent;

    CachedBodyRequest(HttpServletRequest source, byte[] inspectedBody, boolean originalTransferEncodingPresent) {
        super(source);
        this.body = inspectedBody.clone();
        this.originalTransferEncodingPresent = originalTransferEncodingPresent;
    }

    boolean originalTransferEncodingPresent() { return originalTransferEncodingPresent; }

    @Override public ServletInputStream getInputStream() {
        var input = new ByteArrayInputStream(body);
        return new ServletInputStream() {
            @Override public int read() { return input.read(); }
            @Override public int read(byte[] target, int offset, int length) {
                return input.read(target, offset, length);
            }
            @Override public int available() { return input.available(); }
            @Override public boolean isFinished() { return input.available() == 0; }
            @Override public boolean isReady() { return true; }
            @Override public void setReadListener(ReadListener listener) {
                throw new PublicHttpErrors.Rejected(PublicHttpErrors.Error.DEPENDENCY_UNAVAILABLE);
            }
        };
    }

    @Override public BufferedReader getReader() {
        return new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
    }
    @Override public int getContentLength() { return body.length; }
    @Override public long getContentLengthLong() { return body.length; }
    @Override public String getCharacterEncoding() { return StandardCharsets.UTF_8.name(); }

    @Override public String getHeader(String name) {
        if ("Content-Length".equalsIgnoreCase(name)) return Integer.toString(body.length);
        if ("Transfer-Encoding".equalsIgnoreCase(name)) return null;
        return super.getHeader(name);
    }

    @Override public Enumeration<String> getHeaders(String name) {
        if ("Content-Length".equalsIgnoreCase(name)) {
            return Collections.enumeration(Collections.singletonList(Integer.toString(body.length)));
        }
        if ("Transfer-Encoding".equalsIgnoreCase(name)) return Collections.emptyEnumeration();
        return super.getHeaders(name);
    }

    @Override public int getIntHeader(String name) {
        if ("Transfer-Encoding".equalsIgnoreCase(name)) return -1;
        return "Content-Length".equalsIgnoreCase(name) ? body.length : super.getIntHeader(name);
    }

    @Override public long getDateHeader(String name) {
        if ("Transfer-Encoding".equalsIgnoreCase(name)) return -1;
        return super.getDateHeader(name);
    }

    @Override public Enumeration<String> getHeaderNames() {
        var names = new LinkedHashSet<String>();
        var original = super.getHeaderNames();
        if (original != null) {
            while (original.hasMoreElements()) {
                String name = original.nextElement();
                if (!"Content-Length".equalsIgnoreCase(name) && !"Transfer-Encoding".equalsIgnoreCase(name)) {
                    names.add(name);
                }
            }
        }
        names.add("Content-Length");
        return Collections.enumeration(names);
    }

    @Override public boolean isAsyncSupported() { return false; }
    @Override public AsyncContext startAsync() {
        throw new PublicHttpErrors.Rejected(PublicHttpErrors.Error.DEPENDENCY_UNAVAILABLE);
    }
    @Override public AsyncContext startAsync(ServletRequest request, ServletResponse response) {
        throw new PublicHttpErrors.Rejected(PublicHttpErrors.Error.DEPENDENCY_UNAVAILABLE);
    }
}
