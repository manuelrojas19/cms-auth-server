package com.manuelr.microservices.cms.authserver.service;

import com.manuelr.cms.commons.dto.auth.SignupRequestDto;
import com.manuelr.cms.commons.dto.auth.SignupResponseDto;
import com.manuelr.microservices.cms.authserver.dto.SigninRequestDto;
import com.manuelr.microservices.cms.authserver.dto.SigninResponseDto;
import com.manuelr.microservices.cms.authserver.dto.UserDto;
import org.springframework.http.ResponseEntity;

public interface AuthService {
    ResponseEntity<SigninResponseDto> signin(SigninRequestDto request, String accessToken, String refreshToken);
    ResponseEntity<Void> signout(String accessToken, String refreshToken);
    ResponseEntity<SigninResponseDto> refresh(String refreshToken);
    ResponseEntity<SignupResponseDto> signup(SignupRequestDto request);
    ResponseEntity<UserDto> validateToken(String accessToken);
}
