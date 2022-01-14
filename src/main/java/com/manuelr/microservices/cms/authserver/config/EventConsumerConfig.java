package com.manuelr.microservices.cms.authserver.config;

import com.manuelr.cms.commons.enums.RegistrationStatus;
import com.manuelr.cms.commons.event.RegistrationEvent;
import com.manuelr.microservices.cms.authserver.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.function.Consumer;

@Configuration
public class EventConsumerConfig {
    @Autowired
    private SignupStatusHandler signupStatusHandler;

    @Autowired
    private UserRepository userRepository;

    @Bean
    public Consumer<RegistrationEvent> registrationEventConsumer() {
        return registration -> {
            signupStatusHandler.updateUser(registration.getPersonDto().getId(), user -> {
                if (registration.getRegistrationStatus().equals(RegistrationStatus.SUCCESS)) {
                    user.setPersonId(registration.getPersonDto().getId());
                    userRepository.save(user);
                } else {
                    userRepository.delete(user);
                }
            });
        };
    }
}
