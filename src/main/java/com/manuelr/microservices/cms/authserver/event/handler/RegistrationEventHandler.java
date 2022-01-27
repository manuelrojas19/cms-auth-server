package com.manuelr.microservices.cms.authserver.event.handler;

import com.manuelr.cms.commons.event.registration.RegistrationStatus;
import com.manuelr.microservices.cms.authserver.entity.User;
import com.manuelr.microservices.cms.authserver.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.function.Consumer;

@Slf4j
@Service
public class RegistrationEventHandler {

    @Autowired
    private UserRepository userRepository;

    @Transactional
    public void handleRegistration(Long id, Consumer<User> userConsumer, RegistrationStatus status) {
        userRepository.findById(id).ifPresent(userConsumer.andThen(user -> updateOrDeleteUser(user, status)));
    }

    private void updateOrDeleteUser(User user, RegistrationStatus status) {
        if (status.equals(RegistrationStatus.FAILURE)) {
            userRepository.delete(user);
        } else if (status.equals(RegistrationStatus.SUCCESS)) {
            userRepository.save(user);
        }
    }


}
