package com.manuelr.microservices.cms.authserver.config;

import com.manuelr.cms.commons.event.SignupEvent;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Sinks;

import java.util.function.Supplier;

@Configuration
public class EventPublisherConfig {

    @Bean
    public Sinks.Many<SignupEvent> signupSinks() {
        return Sinks.many().multicast().onBackpressureBuffer();
    }

    @Bean
    public Supplier<Flux<SignupEvent>> signupSupplier(Sinks.Many<SignupEvent> sinks) {
        return sinks::asFlux;
    }
}
