package com.manuelr.microservices.cms.authserver.controller;

import com.manuelr.microservices.cms.authserver.dto.*;
import com.manuelr.microservices.cms.authserver.service.AuthService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@AllArgsConstructor
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    private final AuthService authService;

    @PostMapping("/signin")
    public ResponseEntity<SigninResponseDto> signin(
            @CookieValue(name = "accessToken", required = false) String accessToken,
            @CookieValue(name = "refreshToken", required = false) String refreshToken,
            @RequestBody SigninRequestDto request) {
        log.info("Trying to login {}", request);
        return authService.signin(request, accessToken, refreshToken);
    }

    @PostMapping("/signup")
    public ResponseEntity<SignupResponseDto> signUp(@RequestBody SignupRequestDto request) {
        log.info("Trying to signup {}", request);
        return authService.signup(request);
    }

    @PostMapping("/signout")
    public ResponseEntity<Void> signout(
            @CookieValue(name = "accessToken", required = false) String accessToken,
            @CookieValue(name = "refreshToken", required = false) String refreshToken) {
        return authService.signout(accessToken, refreshToken);
    }

    @PostMapping(value = "/refresh_token")
    public ResponseEntity<SigninResponseDto> refreshToken(@CookieValue(name = "accessToken") String accessToken,
                                                          @CookieValue(name = "refreshToken") String refreshToken) {
        return authService.refresh(refreshToken);
    }

    @PostMapping("/validate_token")
    public ResponseEntity<UserDto> validateToken(@CookieValue(name = "accessToken") String accessToken) {
        log.info("Trying to validate token {}", accessToken);
        return authService.validateToken(accessToken);
    }
}
