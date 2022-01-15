package com.manuelr.microservices.cms.authserver.config;

import com.manuelr.cms.commons.event.registration.RegistrationEvent;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.function.Consumer;

@Configuration
public class EventHandlerConfig {

    @Autowired
    private SignupPersonIdHandler handler;

    @Bean
    public Consumer<RegistrationEvent> registrationEventConsumer() {
        return re -> handler.updateOrDeleteUser(re.getPersonDto().getUserId(),
                user -> user.setPersonId(re.getPersonDto().getId()));
    }
}
