package com.finsec.fuse.config;

import com.finsec.fuse.common.Json;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.LinkOption;
import java.nio.file.StandardOpenOption;
import java.nio.channels.Channels;
import com.finsec.fuse.http.InternalKycHttpClient;
import org.springframework.beans.factory.annotation.Autowired;
import java.util.Map;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/** Private document bytes are local runtime assets, never classpath resources. */
@Component
public final class PrivateDocuments {
    public static final String MARKER_PREFIX="FUSE_DOCUMENT_ID:";
    public static final String UNAVAILABLE="PRIVATE_DOCUMENTS_UNAVAILABLE";
    private static final int MAX_FILE_BYTES=1024*1024;
    private static final int MAX_REGISTERED_DOCUMENTS=256;
    private final Json json;private final Environment environment;private final SecurityPolicy policy;
    @Autowired public PrivateDocuments(Json json,Environment environment,SecurityPolicy policy){this.json=json;this.environment=environment;this.policy=policy;}
    public PrivateDocuments(Json json,Environment environment){this(json,environment,InternalKycHttpClient.policy(json));}
    public boolean liveMode(){return "live".equalsIgnoreCase(environment.getProperty("fuse.kyc-mode",environment.getProperty("FUSE_KYC_MODE","replay")));}
    public String resolve(String id,boolean live) {
        if(id==null || !id.matches("[a-z0-9][a-z0-9-]{0,99}"))throw new Unavailable();
        if(!live)return MARKER_PREFIX+id;
        String configured=environment.getProperty("FUSE_PRIVATE_DOCUMENTS_PATH","");
        if(configured.isBlank())throw new Unavailable();
        try {
            Path registered=Path.of(configured);
            for(Path part:registered)if(part.toString().equals(".."))throw new Unavailable();
            Path path=registered.toAbsolutePath();
            for(Path current=path;current!=null;current=current.getParent())
                if(Files.isSymbolicLink(current))throw new Unavailable();
            Path root=path.getParent().toRealPath(LinkOption.NOFOLLOW_LINKS);
            if(!path.toRealPath(LinkOption.NOFOLLOW_LINKS).getParent().equals(root) ||
               !Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS) || Files.size(path)>MAX_FILE_BYTES)throw new Unavailable();
            try(var channel=Files.newByteChannel(path,StandardOpenOption.READ,LinkOption.NOFOLLOW_LINKS);
                var stream=Channels.newInputStream(channel)) {
            byte[] bytes=stream.readNBytes(MAX_FILE_BYTES+1);
            if(bytes.length>MAX_FILE_BYTES)throw new Unavailable();
            String decoded=StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString();
            Map<String,Object> documents=json.map(decoded);
            if(documents==null || documents.size()>MAX_REGISTERED_DOCUMENTS ||
                documents.keySet().stream().anyMatch(key->!key.matches("[a-z0-9][a-z0-9-]{0,99}")) || documents.values().stream().anyMatch(value->!(value instanceof String text) || text.isBlank() ||
                    text.getBytes(StandardCharsets.UTF_8).length>policy.documentTextMaxUtf8Bytes() || isMarker(text)))throw new Unavailable();
            if(!(documents.get(id) instanceof String text))throw new Unavailable();
            return text;
            }
        }catch(IOException|RuntimeException unavailable){
            // Do not expose paths, parser excerpts, private contents, or nested causes in logs.
            throw new Unavailable();
        }
    }
    public static boolean isMarker(String text){return text!=null && text.startsWith(MARKER_PREFIX);}
    public static final class Unavailable extends IllegalStateException {
        public Unavailable(){super(UNAVAILABLE+": configure FUSE_PRIVATE_DOCUMENTS_PATH with the required private document IDs before LIVE execution.");}
    }
}
