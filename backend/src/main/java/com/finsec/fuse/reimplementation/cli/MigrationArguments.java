package com.finsec.fuse.reimplementation.cli;

/** Typed input only: does not inspect a database, descriptor, environment or authority. */
public final class MigrationArguments {
    private final String schema;
    private final int credentialInputFd;

    private MigrationArguments(String schema, int credentialInputFd) {
        this.schema = schema;
        this.credentialInputFd = credentialInputFd;
    }

    public static MigrationArguments parse(String[] args) {
        if (args == null || args.length != 6) throw invalid();
        String[] input = args.clone();
        for (String value : input) if (value == null) throw invalid();
        if (!"fresh-init".equals(input[0])) throw invalid();
        String schema = null;
        Integer descriptor = null;
        boolean expectEmpty = false;
        for (int index = 1; index < input.length; index++) {
            switch (input[index]) {
                case "--schema" -> {
                    if (schema != null || ++index >= input.length) throw invalid();
                    String value = input[index];
                    if (!value.matches("[A-Za-z_][A-Za-z0-9_]{0,62}")) throw invalid();
                    schema = value;
                }
                case "--credential-input-fd" -> {
                    if (descriptor != null || ++index >= input.length) throw invalid();
                    String value = input[index];
                    if (value.length() > 10 || !value.matches("0|[1-9][0-9]*")) throw invalid();
                    long number = 0;
                    for (int offset = 0; offset < value.length(); offset++) {
                        number = number * 10 + value.charAt(offset) - '0';
                    }
                    if (number > Integer.MAX_VALUE) throw invalid();
                    descriptor = (int) number;
                }
                case "--expect-empty" -> {
                    if (expectEmpty) throw invalid();
                    expectEmpty = true;
                }
                default -> throw invalid();
            }
        }
        if (schema == null || descriptor == null || !expectEmpty) throw invalid();
        return new MigrationArguments(schema, descriptor);
    }

    public String schema() { return schema; }
    public int credentialInputFd() { return credentialInputFd; }
    public boolean expectEmpty() { return true; }

    @Override public String toString() { return "MigrationArguments[redacted]"; }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Invalid migration arguments");
    }
}
