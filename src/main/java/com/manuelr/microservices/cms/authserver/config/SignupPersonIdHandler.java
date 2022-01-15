package com.manuelr.microservices.cms.authserver.config;

import com.manuelr.microservices.cms.authserver.entity.User;
import com.manuelr.microservices.cms.authserver.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;
import java.util.function.Consumer;

@Slf4j
@Configuration
public class SignupPersonIdHandler {

    @Autowired
    private UserRepository userRepository;

    @Transactional
    public void updateOrDeleteUser(Long id, Consumer<User> userConsumer) {
        userRepository.findById(id).ifPresent(userConsumer.andThen(this::updateOrDeleteUser));
    }

    private void updateOrDeleteUser(User user) {
        if (Objects.isNull(user.getPersonId())) {
            userRepository.delete(user);
        } else if (Objects.nonNull(user.getPersonId())) {
            userRepository.save(user);
        }
    }


}
