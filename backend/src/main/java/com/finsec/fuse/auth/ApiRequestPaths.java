package com.finsec.fuse.auth;

import jakarta.servlet.http.HttpServletRequest;

/** Protective eligibility only; route and preflight authorization still use the raw URI. */
final class ApiRequestPaths {
    private ApiRequestPaths() {}

    static boolean protectedApi(HttpServletRequest request) {
        // Keep raw coverage even when the container mapping differs. Never decode either value here.
        if(api(request.getRequestURI()))return true;
        String servletPath=request.getServletPath();
        String pathInfo=request.getPathInfo();
        // Covers the root/default DispatcherServlet, including an empty servletPath for /*.
        // Context paths are excluded by the container: guards apply, but raw allowlists still reject.
        // Prefix servlet mappings such as /mvc/* are unsupported; this is not MVC path reconstruction.
        return api((servletPath==null?"":servletPath)+(pathInfo==null?"":pathInfo));
    }

    private static boolean api(String path) {
        return path!=null && (path.equals("/api")||path.startsWith("/api/"));
    }
}
