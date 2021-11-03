package com.manuelr.microservices.cms.authserver.service;

import com.manuelr.microservices.cms.authserver.dto.*;
import com.manuelr.microservices.cms.authserver.entity.User;
import com.manuelr.microservices.cms.authserver.repository.UserRepository;
import com.manuelr.microservices.cms.authserver.util.CookieUtil;
import com.manuelr.microservices.cms.authserver.util.JwtUtil;
import com.manuelr.microservices.cms.authserver.util.SecurityCipher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.nio.CharBuffer;

@Service
public class UserServiceImpl implements UserService {
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private CookieUtil cookieUtil;
    @Autowired
    private JwtUtil jwtUtil;

    @Override
    public ResponseEntity<SigninResponseDto> signin(SigninRequestDto request, String accessToken, String refreshToken) {
        String email = request.getEmail();
        User user = userRepository.findByUsername(email).orElseThrow(
                () -> new IllegalArgumentException("User not found with email " + email));
        if (!passwordEncoder.matches(CharBuffer.wrap(request.getPassword()), user.getPassword())) {
            throw new RuntimeException("Invalid password");
        }

        accessToken = SecurityCipher.decrypt(accessToken);
        refreshToken = SecurityCipher.decrypt(refreshToken);

        boolean accessTokenValid = jwtUtil.validateToken(accessToken);
        boolean refreshTokenValid = jwtUtil.validateToken(refreshToken);

        HttpHeaders responseHeaders = new HttpHeaders();
        Token newAccessToken;
        Token newRefreshToken;

        if (!accessTokenValid && !refreshTokenValid || accessTokenValid && refreshTokenValid) {
            newAccessToken = jwtUtil.generateAccessToken(user.getUsername());
            newRefreshToken = jwtUtil.generateRefreshToken(user.getUsername());
            addAccessTokenCookie(responseHeaders, newAccessToken);
            addRefreshTokenCookie(responseHeaders, newRefreshToken);
        }

        if (!accessTokenValid && refreshTokenValid) {
            newAccessToken = jwtUtil.generateAccessToken(user.getUsername());
            addAccessTokenCookie(responseHeaders, newAccessToken);
        }

        SigninResponseDto response = new
                SigninResponseDto(SigninResponseDto.SuccessFailure.SUCCESS,
                "Auth successful. Tokens are created in cookie.");
        return ResponseEntity.ok().headers(responseHeaders).body(response);
    }

    @Override
    public ResponseEntity<SigninResponseDto> refresh(String refreshToken) {
        refreshToken = SecurityCipher.decrypt(refreshToken);

        boolean refreshTokenValid = jwtUtil.validateToken(refreshToken);

        if (!refreshTokenValid) {
            throw new IllegalArgumentException("Refresh Token is invalid!");
        }

        String currentUserEmail = jwtUtil.getUsernameFromToken(refreshToken);

        Token newAccessToken = jwtUtil.generateAccessToken(currentUserEmail);

        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add(HttpHeaders.SET_COOKIE, cookieUtil.createAccessTokenCookie(newAccessToken.getTokenValue(),
                newAccessToken.getDuration()).toString());

        SigninResponseDto loginResponse = new SigninResponseDto(SigninResponseDto.SuccessFailure.SUCCESS,
                "Auth successful. Tokens are created in cookie.");
        return ResponseEntity.ok().headers(responseHeaders).body(loginResponse);
    }

    @Override
    public ResponseEntity<SignupResponseDto> signup(SignupRequestDto request) {
        String email = request.getEmail();
        if (userRepository.existsByUsername(email)) {
            throw new RuntimeException("Email is already taken");
        }

        User user = new User(request.getEmail(), request.getPassword(), request.getRole());
        userRepository.save(user);

        HttpHeaders responseHeaders = new HttpHeaders();

        Token accessToken = jwtUtil.generateAccessToken(email);
        Token refreshToken = jwtUtil.generateRefreshToken(email);

        addAccessTokenCookie(responseHeaders, accessToken);
        addRefreshTokenCookie(responseHeaders, refreshToken);

        SignupResponseDto response = new SignupResponseDto(SignupResponseDto.SuccessFailure.SUCCESS,
                "Auth successful. User registered Tokens are created in cookie.");
        return ResponseEntity.ok().headers(responseHeaders).body(response);
    }

    @Override
    public ResponseEntity<UserDto> validateToken(String accessToken) {
        accessToken = SecurityCipher.decrypt(accessToken);
        if (!StringUtils.hasText(accessToken) || !jwtUtil.validateToken(accessToken))
            throw new RuntimeException("Invalid token");
        String email = jwtUtil.getUsernameFromToken(accessToken);
        User user = userRepository.findByUsername(email).orElseThrow(() -> new RuntimeException("User not found"));
        return ResponseEntity.ok().body(UserDto.builder().id(user.getId()).email(user.getUsername()).role(user.getRole()).build());
    }

    private void addAccessTokenCookie(HttpHeaders httpHeaders, Token token) {
        httpHeaders.add(HttpHeaders.SET_COOKIE, cookieUtil
                .createAccessTokenCookie(token.getTokenValue(), token.getDuration()).toString());
    }

    private void addRefreshTokenCookie(HttpHeaders httpHeaders, Token token) {
        httpHeaders.add(HttpHeaders.SET_COOKIE, cookieUtil
                .createRefreshTokenCookie(token.getTokenValue(), token.getDuration()).toString());
    }
}
