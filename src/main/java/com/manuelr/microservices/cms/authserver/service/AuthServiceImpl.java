package com.manuelr.microservices.cms.authserver.service;

import com.manuelr.microservices.cms.authserver.dto.*;
import com.manuelr.microservices.cms.authserver.entity.User;
import com.manuelr.microservices.cms.authserver.repository.UserRepository;
import com.manuelr.microservices.cms.authserver.util.CookieUtil;
import com.manuelr.microservices.cms.authserver.util.JwtTokenUtil;
import com.manuelr.microservices.cms.authserver.util.SecurityCipher;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.nio.CharBuffer;

@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final UserRepository userRepository;

    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;

    private final CookieUtil cookieUtil;
    private final JwtTokenUtil jwtTokenUtil;

    @Override
    public ResponseEntity<SigninResponseDto> signin(SigninRequestDto request, String accessToken, String refreshToken) {
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String email = request.getEmail();

        User user = userRepository.findByUsername(email).orElseThrow(
                () -> new IllegalArgumentException("User not found with email " + email));

        accessToken = SecurityCipher.decrypt(accessToken);
        refreshToken = SecurityCipher.decrypt(refreshToken);

        boolean accessTokenValid = jwtTokenUtil.validateToken(accessToken);
        boolean refreshTokenValid = jwtTokenUtil.validateToken(refreshToken);

        HttpHeaders responseHeaders = new HttpHeaders();
        Token newAccessToken;
        Token newRefreshToken;

        if (!accessTokenValid && !refreshTokenValid || accessTokenValid && refreshTokenValid) {
            newAccessToken = jwtTokenUtil.generateAccessToken(user.getUsername());
            newRefreshToken = jwtTokenUtil.generateRefreshToken(user.getUsername());
            addAccessTokenCookie(responseHeaders, newAccessToken);
            addRefreshTokenCookie(responseHeaders, newRefreshToken);
        }

        if (!accessTokenValid && refreshTokenValid) {
            newAccessToken = jwtTokenUtil.generateAccessToken(user.getUsername());
            addAccessTokenCookie(responseHeaders, newAccessToken);
        }

        SigninResponseDto response = new
                SigninResponseDto(SigninResponseDto.SuccessFailure.SUCCESS,
                "Auth successful. Tokens are created in cookie.");
        return ResponseEntity.ok().headers(responseHeaders).body(response);
    }

    @Override
    public ResponseEntity<Void> signout(String accessToken, String refreshToken) {
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add(HttpHeaders.SET_COOKIE, cookieUtil.deleteRefreshTokenCookie().toString());
        responseHeaders.add(HttpHeaders.SET_COOKIE, cookieUtil.deleteAccessTokenCookie().toString());
        return ResponseEntity.noContent().headers(responseHeaders).build();
    }

    @Override
    public ResponseEntity<SigninResponseDto> refresh(String refreshToken) {
        refreshToken = SecurityCipher.decrypt(refreshToken);

        boolean refreshTokenValid = jwtTokenUtil.validateToken(refreshToken);

        if (!refreshTokenValid) {
            throw new IllegalArgumentException("Refresh Token is invalid!");
        }

        String currentUserEmail = jwtTokenUtil.getUsernameFromToken(refreshToken);

        Token newAccessToken = jwtTokenUtil.generateAccessToken(currentUserEmail);

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

        User user = new User(email, passwordEncoder.encode(request.getPassword()), request.getRole());
        userRepository.save(user);

        HttpHeaders responseHeaders = new HttpHeaders();

        Token accessToken = jwtTokenUtil.generateAccessToken(email);
        Token refreshToken = jwtTokenUtil.generateRefreshToken(email);

        addAccessTokenCookie(responseHeaders, accessToken);
        addRefreshTokenCookie(responseHeaders, refreshToken);

        SignupResponseDto response = new SignupResponseDto(SignupResponseDto.SuccessFailure.SUCCESS,
                "Auth successful. User registered Tokens are created in cookie.");
        return ResponseEntity.ok().headers(responseHeaders).body(response);
    }

    @Override
    public ResponseEntity<UserDto> validateToken(String accessToken) {
        accessToken = SecurityCipher.decrypt(accessToken);
        if (!StringUtils.hasText(accessToken) || !jwtTokenUtil.validateToken(accessToken))
            throw new RuntimeException("Invalid token");
        String email = jwtTokenUtil.getUsernameFromToken(accessToken);
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
