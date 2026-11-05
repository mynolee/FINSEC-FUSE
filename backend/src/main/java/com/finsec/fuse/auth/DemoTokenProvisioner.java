package com.finsec.fuse.auth;

import com.finsec.fuse.reimplementation.cli.TokenAdminCommandRunner;
import java.io.PrintStream;
import java.util.Objects;

/** Token CLI entrypoint. No native/admin backend discovery or operational adapter is installed. */
public final class DemoTokenProvisioner {
    private DemoTokenProvisioner() { }
    public static int run(String[] args,PrintStream metadata){
        Objects.requireNonNull(metadata);
        TokenAdminCommandRunner.CommandOutcome outcome;
        try{outcome=TokenAdminCommandRunner.execute(args,null);}
        catch(Throwable unavailable){outcome=TokenAdminCommandRunner.unknown();}
        try{
            metadata.print(outcome.metadataJson());metadata.flush();
            return metadata.checkError()?4:outcome.exitCode();
        }catch(Throwable unavailable){return 4;}
    }
    public static void main(String[] args){System.exit(run(args,System.out));}
}
