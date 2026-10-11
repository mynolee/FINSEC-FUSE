package com.finsec.fuse.workflow;

public interface KycGateway {
    KycContract.Response evaluate(KycContract.Input input);
}
