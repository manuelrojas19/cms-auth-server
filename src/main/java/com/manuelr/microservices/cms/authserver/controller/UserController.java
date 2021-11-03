package com.manuelr.microservices.cms.authserver.controller;

import com.manuelr.microservices.cms.authserver.dto.*;
import com.manuelr.microservices.cms.authserver.service.UserService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@AllArgsConstructor
@Slf4j
public class UserController {
    private final UserService userService;

    @PostMapping("/api/v1/users/signin")
    public ResponseEntity<SigninResponseDto> signin(
            @CookieValue(name = "accessToken", required = false) String accessToken,
            @CookieValue(name = "refreshToken", required = false) String refreshToken,
            @RequestBody SigninRequestDto request) {
        log.info("Trying to login {}", request);
        return userService.signin(request, accessToken, refreshToken);
    }

    @PostMapping("/api/v1/users/signup")
    public ResponseEntity<SignupResponseDto> signUp(@RequestBody SignupRequestDto request) {
        log.info("Trying to signup {}", request);
        return userService.signup(request);
    }

    @PostMapping(value = "/api/v1/users/refresh_token")
    public ResponseEntity<SigninResponseDto> refreshToken(@CookieValue(name = "accessToken") String accessToken,
                                                          @CookieValue(name = "refreshToken") String refreshToken) {
        return userService.refresh(refreshToken);
    }

    @PostMapping("/api/v1/users/validate_token")
    public ResponseEntity<UserDto> validateToken(@CookieValue(name = "accessToken") String accessToken) {
        log.info("Trying to validate token {}", accessToken);
        return userService.validateToken(accessToken);
    }
}
