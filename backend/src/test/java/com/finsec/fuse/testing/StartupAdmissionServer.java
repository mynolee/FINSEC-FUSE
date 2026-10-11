package com.finsec.fuse.testing;

import com.finsec.fuse.FuseApplication;
import java.io.*;
import java.net.URL;
import java.nio.file.*;
import java.util.*;
import org.springframework.boot.SpringApplication;
import tools.jackson.databind.json.JsonMapper;

/** Child JVM only. No substituted Spring beans, worker calls, or production bypass flags. */
public final class StartupAdmissionServer {
    public static void main(String[] args) throws Exception {
        if(args.length!=1)throw new IllegalArgumentException("Expected private temporary config");
        Map<?,?> config=JsonMapper.builder().build().readValue(Files.readString(Path.of(args[0])),Map.class);
        String fault=String.valueOf(config.get("fault"));
        // Exercise the actual ClassPathResource loader, without modifying repository resources.
        if(Set.of("MISSING_POLICY","INVALID_POLICY").contains(fault)) {
            Path replacement=Path.of(String.valueOf(config.get("invalidPolicy")));
            ClassLoader parent=Thread.currentThread().getContextClassLoader();
            Thread.currentThread().setContextClassLoader(new ClassLoader(parent) {
                private boolean target(String name){return "config/demo_policy.json".equals(name);}
                @Override public URL getResource(String name) {
                    if(!target(name))return super.getResource(name);
                    try{return "MISSING_POLICY".equals(fault)?null:replacement.toUri().toURL();}
                    catch(Exception failure){throw new IllegalStateException(failure);}
                }
                @Override public Enumeration<URL> getResources(String name)throws IOException {
                    if(!target(name))return super.getResources(name);
                    URL value=getResource(name);return Collections.enumeration(value==null?List.of():List.of(value));
                }
                @Override public InputStream getResourceAsStream(String name) {
                    if(!target(name))return super.getResourceAsStream(name);
                    try{URL value=getResource(name);return value==null?null:value.openStream();}
                    catch(IOException failure){throw new UncheckedIOException(failure);}
                }
            });
        }
        var options=new ArrayList<String>();
        for(Object option:(List<?>)config.get("options"))options.add(option.toString());
        var context=new SpringApplication(FuseApplication.class).run(options.toArray(String[]::new));
        Files.writeString(Path.of(config.get("started").toString()),ProcessHandle.current().pid()+":"+context.getEnvironment().getRequiredProperty("local.server.port"));
    }
}
