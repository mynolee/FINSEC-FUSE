package com.finsec.fuse.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@Configuration
public class TransactionConfiguration {
    @Bean public TransactionTemplate transactionTemplate(PlatformTransactionManager manager) {return new TransactionTemplate(manager);}
}
