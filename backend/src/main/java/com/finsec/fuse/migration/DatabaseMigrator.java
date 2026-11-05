package com.finsec.fuse.migration;

import com.finsec.fuse.reimplementation.cli.MigrationArguments;

/** Exact declared jar entry. No operational adapter, environment or credential fallback. */
public final class DatabaseMigrator {
    private DatabaseMigrator() {}
    public static MigrationCommandRunner.Outcome execute(String[] args,MigrationCommandRunner.PreparedBackend backend){
        final MigrationArguments parsed;
        try{parsed=MigrationArguments.parse(args);}
        catch(IllegalArgumentException rejected){return new MigrationCommandRunner.Outcome(
            MigrationCommandRunner.Status.INPUT_REJECTED,java.util.List.of(),MigrationCommandRunner.Cleanup.NOT_OPENED,false);}
        return MigrationCommandRunner.run(parsed,backend);
    }
    public static void main(String[] args){
        // No native/admin/Flyway adapter is installed: valid input is UNCONFIGURED before effects.
        System.exit(execute(args,null).exitCode());
    }
}
