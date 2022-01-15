package com.manuelr.microservices.cms.authserver.service.event;

import com.manuelr.cms.commons.dto.SignupRequestDto;
import com.manuelr.cms.commons.event.signup.SignupEvent;
import com.manuelr.cms.commons.event.signup.SignupStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Sinks;

@Service
public class SignupStatusPublisher {

    @Autowired
    private Sinks.Many<SignupEvent> signupSinks;

    public void raiseSignupEvent(SignupRequestDto signupRequestDto, SignupStatus signupStatus) {
        SignupEvent signupEvent = new SignupEvent(signupRequestDto, signupStatus);
        signupSinks.tryEmitNext(signupEvent);
    }
}
