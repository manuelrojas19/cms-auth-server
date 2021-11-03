package com.manuelr.microservices.cms.authserver.service;

import com.manuelr.microservices.cms.authserver.dto.*;
import org.springframework.http.ResponseEntity;

public interface UserService {
    ResponseEntity<SigninResponseDto> signin(SigninRequestDto request, String accessToken, String refreshToken);
    ResponseEntity<SigninResponseDto> refresh(String refreshToken);
    ResponseEntity<SignupResponseDto> signup(SignupRequestDto request);
    ResponseEntity<UserDto> validateToken(String accessToken);
}
