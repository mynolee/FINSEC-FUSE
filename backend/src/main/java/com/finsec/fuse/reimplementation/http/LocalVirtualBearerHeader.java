package com.finsec.fuse.reimplementation.http;

import com.finsec.fuse.reimplementation.simulation.SimulationFailure;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.Objects;

/** Single canonical opaque credential extraction; no authentication or role inference. */
public final class LocalVirtualBearerHeader {
    private LocalVirtualBearerHeader() { }
    /** Returned credential is transient sensitive input; never log, persist or attach it to a request. */
    public static String canonical(HttpServletRequest request) {
        Objects.requireNonNull(request);
        var values=request.getHeaders("Authorization");
        if(values==null||!values.hasMoreElements())throw SimulationFailure.unauthenticated();
        String header=values.nextElement();
        if(values.hasMoreElements()||header==null||header.length()!=50
                ||!header.regionMatches(true,0,"Bearer",0,6)||header.charAt(6)!=' ')
            throw SimulationFailure.unauthenticated();
        String token=header.substring(7);
        for(int i=0;i<token.length();i++) {
            char c=token.charAt(i);
            if(!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'||c=='_'))
                throw SimulationFailure.unauthenticated();
        }
        try {
            byte[] decoded=Base64.getUrlDecoder().decode(token);
            try {
                if(decoded.length!=32||!Base64.getUrlEncoder().withoutPadding().encodeToString(decoded).equals(token))
                    throw SimulationFailure.unauthenticated();
            } finally { java.util.Arrays.fill(decoded,(byte)0); }
        } catch(IllegalArgumentException malformed) { throw SimulationFailure.unauthenticated(); }
        return token;
    }
}
