package com.finsec.fuse.auth;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.sql.*;
import java.util.*;

/** Standalone, explicitly invoked owner operation. Does not start Spring, migrate, or import tokens. */
public final class DemoTokenProvisioner {
    private DemoTokenProvisioner() {}
    private static final class Fresh {
        private final String variable,token;private final DemoTokenStore.Binding binding;
        Fresh(String variable,String token,DemoTokenStore.Binding binding){this.variable=variable;this.token=token;this.binding=binding;}
        String variable(){return variable;}String token(){return token;}DemoTokenStore.Binding binding(){return binding;}
        @Override public String toString(){return "Fresh credential (redacted)";}
    }
    public static void main(String[] args) {
        UUID operation=UUID.randomUUID();
        try {
            execute(args,System.getenv(),operation);
            System.out.println("Authentication operation COMMITTED. Operation ID: "+operation);
        } catch(Exception failure) {
            // Never expose a driver exception, connection string, configuration value, or bearer.
            System.err.println("Authentication operation not confirmed. Operation ID: "+operation+
                ". Preserve any PREPARED private output and reconcile database fingerprints before retrying.");
            System.exit(1);
        }
    }
    static void execute(String[] args,Map<String,String> environment,UUID operation)throws Exception {
        if(args.length==0||args.length>16)throw new IllegalArgumentException("Invalid operation");
        String command=args[0];Map<String,String> options=options(args);
        switch(command) {
            case "init-fresh" -> {
                only(options,Set.of("new-install","output"));required(options,"new-install");
                // Generate new credentials only. Existing environment bearer values are never read.
                List<Fresh> fresh=initialCredentials(environment);
                try(PrivateOutput output=PrivateOutput.create(Path.of(required(options,"output")))) {
                    output.write(prepared(operation,fresh));
                    try(Connection connection=owner(environment)) {
                        DemoTokenAdministration.initialize(connection,fresh.stream().map(Fresh::binding).toList());
                    }
                    output.write("\n# status=COMMITTED\n");
                }
            }
            case "issue-fresh" -> {
                only(options,Set.of("actor","role","scope","output","replace"));
                Actor actor=new Actor(required(options,"actor"),required(options,"role"),scope(requiredAllowEmpty(options,"scope")));
                DemoTokenStore.validateActor(actor);
                Fresh fresh=fresh("FUSE_FRESH_TOKEN",actor);
                Set<String> replacements=fingerprints(options.getOrDefault("replace",""));
                try(PrivateOutput output=PrivateOutput.create(Path.of(required(options,"output")))) {
                    output.write(prepared(operation,List.of(fresh)));
                    try(Connection connection=owner(environment)) {DemoTokenAdministration.issue(connection,fresh.binding(),replacements);}
                    output.write("\n# status=COMMITTED\n");
                }
            }
            case "revoke" -> {
                only(options,Set.of("actor","fingerprint"));
                if(options.containsKey("actor")==options.containsKey("fingerprint"))throw new IllegalArgumentException("Select exactly one target");
                try(Connection connection=owner(environment)) {
                    if(options.containsKey("actor"))DemoTokenAdministration.revokeActor(connection,required(options,"actor"));
                    else DemoTokenAdministration.revokeFingerprint(connection,required(options,"fingerprint"));
                }
            }
            case "update-scope" -> {
                only(options,Set.of("actor","scope"));
                try(Connection connection=owner(environment)) {DemoTokenAdministration.updateScope(connection,required(options,"actor"),scope(requiredAllowEmpty(options,"scope")));}
            }
            default -> throw new IllegalArgumentException("Unknown operation");
        }
    }
    private static Connection owner(Map<String,String> environment)throws SQLException {
        String url=required(environment,"FUSE_DB_URL"),user=required(environment,"FUSE_MIGRATION_USERNAME"),password=requiredAllowEmpty(environment,"FUSE_MIGRATION_PASSWORD");
        if(!url.startsWith("jdbc:postgresql:")||"fuse_runtime".equals(user))throw new IllegalArgumentException("An existing migration owner is required");
        Properties properties=new Properties();properties.setProperty("user",user);properties.setProperty("password",password);
        properties.setProperty("connectTimeout","5");properties.setProperty("socketTimeout","10");
        Connection connection=DriverManager.getConnection(url,properties);
        try {
            try(Statement statement=connection.createStatement()) {
                statement.setQueryTimeout(5);statement.execute("SET lock_timeout='2s'; SET statement_timeout='5s'");
                try(ResultSet result=statement.executeQuery("SELECT count(*)=2 AND bool_and(pg_has_role(current_user,relowner,'USAGE')) FROM pg_class WHERE oid IN (to_regclass('demo_auth_registry'),to_regclass('demo_token'))")) {
                    if(!result.next()||!result.getBoolean(1))throw new SQLException("Existing migrated owner authority required","42501");
                }
            }
            return connection;
        } catch(SQLException|RuntimeException failure) {connection.close();throw failure;}
    }
    private static List<Fresh> initialCredentials(Map<String,String> environment) {
        List<Fresh> result=new ArrayList<>();Set<String> defaults=Set.of("customer-101","customer-102","customer-103","customer-104");
        for(int n=101;n<=104;n++)result.add(fresh("FUSE_CUSTOMER_"+n+"_TOKEN",new Actor("customer-"+n,"CUSTOMER",Set.of("customer-"+n))));
        result.add(fresh("FUSE_REVIEWER_TOKEN",new Actor("staff-01","LOAN_REVIEWER",environment.containsKey("FUSE_REVIEWER_CUSTOMERS")?scope(environment.get("FUSE_REVIEWER_CUSTOMERS")):defaults)));
        result.add(fresh("FUSE_SECURITY_TOKEN",new Actor("security-01","SECURITY_OPERATOR",environment.containsKey("FUSE_SECURITY_CUSTOMERS")?scope(environment.get("FUSE_SECURITY_CUSTOMERS")):defaults)));
        result.add(fresh("FUSE_DEVELOPER_TOKEN",new Actor("developer-01","DEVELOPER",Set.of())));
        result.add(fresh("FUSE_SERVICE_TOKEN",new Actor("kyc-service","KYC_SERVICE",Set.of())));
        return List.copyOf(result);
    }
    private static Fresh fresh(String variable,Actor actor) {
        String token=DevActorRegistry.generateToken();return new Fresh(variable,token,new DemoTokenStore.Binding(DevActorRegistry.fingerprint(token),actor));
    }
    private static String prepared(UUID operation,List<Fresh> credentials) {
        StringBuilder content=new StringBuilder("# Fresh private bearer output. Keep private; hand off explicitly.\n# operation_id=").append(operation).append("\n# status=PREPARED\n");
        for(Fresh fresh:credentials)content.append("# actor=").append(fresh.binding().actor().actorId()).append(" fingerprint=").append(fresh.binding().fingerprint()).append('\n')
            .append(fresh.variable()).append('=').append(fresh.token()).append('\n');
        return content.toString();
    }
    private static Map<String,String> options(String[] args) {
        Map<String,String> parsed=new HashMap<>();
        for(int i=1;i<args.length;i++) {
            String key=args[i];if(!key.startsWith("--"))throw new IllegalArgumentException("Invalid option");key=key.substring(2);
            String value="new-install".equals(key)?"true":i+1<args.length?args[++i]:null;
            if(value==null||parsed.putIfAbsent(key,value)!=null)throw new IllegalArgumentException("Invalid option");
        }
        return parsed;
    }
    private static void only(Map<String,String> options,Set<String> supported) {if(!supported.containsAll(options.keySet()))throw new IllegalArgumentException("Unsupported option");}
    private static String required(Map<String,String> values,String name) {
        String value=requiredAllowEmpty(values,name);if(value.isBlank())throw new IllegalArgumentException("Required option is missing");return value;
    }
    private static String requiredAllowEmpty(Map<String,String> values,String name) {
        String value=values.get(name);if(value==null)throw new IllegalArgumentException("Required option is missing");return value;
    }
    private static Set<String> scope(String source) {
        if(source.length()>32768)throw new IllegalArgumentException("Invalid scope");
        Set<String> values=new HashSet<>();for(String value:source.split(",")){if(!value.isBlank())values.add(value.trim());}
        return DemoTokenStore.canonicalScope(values);
    }
    private static Set<String> fingerprints(String source) {
        if(source.isEmpty())return Set.of();if(source.length()>16640)throw new IllegalArgumentException("Invalid replacement list");
        var values=new TreeSet<String>();for(String value:source.split(",",-1)){DemoTokenStore.validateFingerprint(value);values.add(value);}return values;
    }
    /** Descriptor-relative traversal and CREATE_NEW prevent symlink following and overwrite races. */
    private static final class PrivateOutput implements AutoCloseable {
        private final SecureDirectoryStream<Path> directory;private final SeekableByteChannel channel;
        private PrivateOutput(SecureDirectoryStream<Path> directory,SeekableByteChannel channel){this.directory=directory;this.channel=channel;}
        static PrivateOutput create(Path supplied)throws IOException {
            if(!supplied.isAbsolute()||!supplied.equals(supplied.normalize())||supplied.getFileName()==null)throw new IOException("Use an absolute normalized output path");
            UserPrincipal owner=FileSystems.getDefault().getUserPrincipalLookupService().lookupPrincipalByName(System.getProperty("user.name"));
            if("root".equals(owner.getName()))throw new IOException("Use a non-root owner");
            DirectoryStream<Path> root=Files.newDirectoryStream(supplied.getRoot());
            if(!(root instanceof SecureDirectoryStream<Path> current)){root.close();throw new IOException("Secure output creation is unavailable");}
            SeekableByteChannel channel=null;
            try {
                for(Path part:supplied.getRoot().relativize(supplied.getParent())) {
                    SecureDirectoryStream<Path> next=current.newDirectoryStream(part,LinkOption.NOFOLLOW_LINKS);current.close();current=next;
                }
                PosixFileAttributes attributes=current.getFileAttributeView(PosixFileAttributeView.class).readAttributes();
                if(!attributes.isDirectory()||!attributes.owner().equals(owner)||!attributes.permissions().equals(PosixFilePermissions.fromString("rwx------")))throw new IOException("Output directory must be private and owner-owned");
                channel=current.newByteChannel(supplied.getFileName(),Set.of(StandardOpenOption.WRITE,StandardOpenOption.CREATE_NEW,LinkOption.NOFOLLOW_LINKS),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
                if(!(channel instanceof FileChannel))throw new IOException("Durable private output is unavailable");
                PosixFileAttributes file=current.getFileAttributeView(supplied.getFileName(),PosixFileAttributeView.class,LinkOption.NOFOLLOW_LINKS).readAttributes();
                if(!file.isRegularFile()||!file.owner().equals(owner)||!file.permissions().equals(PosixFilePermissions.fromString("rw-------")))throw new IOException("Output file must be private and owner-owned");
                return new PrivateOutput(current,channel);
            } catch(IOException|RuntimeException failure) {if(channel!=null)channel.close();current.close();throw failure;}
        }
        void write(String value)throws IOException {
            ByteBuffer bytes=StandardCharsets.UTF_8.encode(value);while(bytes.hasRemaining())channel.write(bytes);((FileChannel)channel).force(true);
            try(SeekableByteChannel entry=directory.newByteChannel(Path.of("."),Set.of(StandardOpenOption.READ,LinkOption.NOFOLLOW_LINKS))) {
                if(!(entry instanceof FileChannel file))throw new IOException("Durable directory output is unavailable");file.force(true);
            }
        }
        @Override public void close()throws IOException {try{channel.close();}finally{directory.close();}}
    }
}
