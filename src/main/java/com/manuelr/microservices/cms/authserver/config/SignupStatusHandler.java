package com.manuelr.microservices.cms.authserver.config;

import com.manuelr.cms.commons.dto.auth.SignupRequestDto;
import com.manuelr.cms.commons.enums.Role;
import com.manuelr.microservices.cms.authserver.dto.UserDto;
import com.manuelr.microservices.cms.authserver.entity.User;
import com.manuelr.microservices.cms.authserver.repository.UserRepository;
import com.manuelr.microservices.cms.authserver.service.event.SignupStatusPublisher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;

import java.util.function.Consumer;

@Configuration
public class SignupStatusHandler {

    @Autowired
    private UserRepository userRepository;

    public void updateUser(Long id, Consumer<User> userConsumer) {
        userRepository.findById(id).ifPresent(userConsumer);

    }
}
