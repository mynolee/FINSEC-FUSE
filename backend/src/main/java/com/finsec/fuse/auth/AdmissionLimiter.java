package com.finsec.fuse.auth;

import com.finsec.fuse.config.SecurityPolicy;
import java.time.Clock;
import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/** Atomic, bounded, per-instance fixed 60-second windows. Never trusts forwarded IP headers. */
@Component
public final class AdmissionLimiter {
    private record Window(long startsAt,int count) {}
    private final Map<String,Window> windows=new HashMap<>();
    private static final int MAX_KEYS=10000;
    private final Clock clock;private final SecurityPolicy policy;
    @Autowired public AdmissionLimiter(SecurityPolicy policy){this(policy,Clock.systemUTC());}
    public AdmissionLimiter(SecurityPolicy policy,Clock clock){this.policy=policy;this.clock=clock;}
    public boolean anonymous(String remoteAddress){return accept("ip:"+remoteAddress,policy.anonymousAttemptsPerIpPerMinute());}
    public boolean actor(Actor actor,boolean read){return accept("actor:"+actor.actorId()+":"+(read?"read":"change"),read?policy.authenticatedReadsPerMinute():policy.authenticatedChangesPerMinute());}
    private synchronized boolean accept(String key,int limit){
        long now=clock.millis();
        windows.entrySet().removeIf(e->now-e.getValue().startsAt()>=60000);
        Window window=windows.get(key);
        if(window==null){if(windows.size()>=MAX_KEYS)return false;windows.put(key,new Window(now,1));return true;}
        if(window.count()>=limit)return false;
        windows.put(key,new Window(window.startsAt(),window.count()+1));return true;
    }
}
