package com.manuelr.microservices.cms.authserver.event;

import com.manuelr.cms.commons.event.registration.RegistrationEvent;
import com.manuelr.microservices.cms.authserver.event.handler.RegistrationEventHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.function.Consumer;

@Configuration
public class EventHandlerConfig {

    @Autowired
    private RegistrationEventHandler registrationEventHandler;

    @Bean
    public Consumer<RegistrationEvent> registrationEventConsumer() {
        return re -> registrationEventHandler.handleRegistration(re.getPersonDto().getUserId(),
                user -> user.setPersonId(re.getPersonDto().getId()), re.getRegistrationStatus());
    }
}
