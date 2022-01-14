package com.manuelr.microservices.cms.authserver.service.impl;

import com.manuelr.cms.commons.dto.auth.SignupRequestDto;
import com.manuelr.cms.commons.dto.auth.SignupResponseDto;
import com.manuelr.cms.commons.enums.SignupStatus;
import com.manuelr.cms.commons.security.SecurityCipher;
import com.manuelr.microservices.cms.authserver.dto.SigninRequestDto;
import com.manuelr.microservices.cms.authserver.dto.SigninResponseDto;
import com.manuelr.microservices.cms.authserver.dto.Token;
import com.manuelr.microservices.cms.authserver.dto.UserDto;
import com.manuelr.microservices.cms.authserver.entity.Role;
import com.manuelr.microservices.cms.authserver.entity.User;
import com.manuelr.microservices.cms.authserver.exception.BadRequestException;
import com.manuelr.microservices.cms.authserver.exception.ConflictException;
import com.manuelr.microservices.cms.authserver.repository.UserRepository;
import com.manuelr.microservices.cms.authserver.service.AuthService;
import com.manuelr.microservices.cms.authserver.service.event.SignupStatusPublisher;
import com.manuelr.microservices.cms.authserver.util.CookieUtil;
import com.manuelr.microservices.cms.authserver.util.JwtTokenUtil;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Slf4j
@Service
@AllArgsConstructor
public class AuthServiceImpl implements AuthService {
    private static final String AUTH_SUCCESSFUL_MSG = "Authentication was successful. Tokens are created in cookie.";

    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final SignupStatusPublisher signupStatusPublisher;
    private final PasswordEncoder passwordEncoder;
    private final CookieUtil cookieUtil;
    private final JwtTokenUtil jwtTokenUtil;

    @Override
    @Transactional(readOnly = true)
    public ResponseEntity<SigninResponseDto> signin(SigninRequestDto request, String accessToken, String refreshToken) {
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        User user = userRepository.findByEmail(request.getEmail()).orElseThrow(
                () -> new IllegalArgumentException("User not found"));

        accessToken = SecurityCipher.decrypt(accessToken);
        refreshToken = SecurityCipher.decrypt(refreshToken);

        boolean accessTokenValid = jwtTokenUtil.validateToken(accessToken);
        boolean refreshTokenValid = jwtTokenUtil.validateToken(refreshToken);

        HttpHeaders responseHeaders = new HttpHeaders();
        Token newAccessToken;
        Token newRefreshToken;

        if (!accessTokenValid && !refreshTokenValid || accessTokenValid && refreshTokenValid) {
            newAccessToken = jwtTokenUtil.generateAccessToken(user);
            newRefreshToken = jwtTokenUtil.generateRefreshToken(user);
            addAccessTokenCookie(responseHeaders, newAccessToken);
            addRefreshTokenCookie(responseHeaders, newRefreshToken);
        }

        if (!accessTokenValid && refreshTokenValid) {
            newAccessToken = jwtTokenUtil.generateAccessToken(user);
            addAccessTokenCookie(responseHeaders, newAccessToken);
        }

        SigninResponseDto response = new
                SigninResponseDto(SigninResponseDto.SuccessFailure.SUCCESS,
                AUTH_SUCCESSFUL_MSG);
        return ResponseEntity.ok().headers(responseHeaders).body(response);
    }

    @Override
    @Transactional
    public ResponseEntity<SignupResponseDto> signup(SignupRequestDto request) {
        if (userRepository.existsByEmail(request.getEmail())) throw new ConflictException("Email is already taken");
        User user = userRepository.save(new User(request.getEmail(), passwordEncoder
                .encode(request.getPassword()), Role.valueOf(request.getRole().name())));

        request.setUserId(user.getId());
        request.getPersonData().setEmail(user.getEmail());
        request.getPersonData().setUserId(user.getId());

        log.info("Publishing event, data --> {}", request);

        signupStatusPublisher.publishSignupEvent(request, SignupStatus.SUCCESS);

        Token accessToken = jwtTokenUtil.generateAccessToken(user);
        Token refreshToken = jwtTokenUtil.generateRefreshToken(user);

        HttpHeaders responseHeaders = new HttpHeaders();
        addAccessTokenCookie(responseHeaders, accessToken);
        addRefreshTokenCookie(responseHeaders, refreshToken);
        SignupResponseDto response = new SignupResponseDto(SignupResponseDto.SuccessFailure.SUCCESS,
                AUTH_SUCCESSFUL_MSG);
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
    @Transactional(readOnly = true)
    public ResponseEntity<UserDto> validateToken(String accessToken) {
        accessToken = SecurityCipher.decrypt(accessToken);
        if (!StringUtils.hasText(accessToken) || !jwtTokenUtil.validateToken(accessToken))
            throw new BadRequestException("Invalid token, please authenticate");
        String email = jwtTokenUtil.getUsernameFromToken(accessToken);
        User user = userRepository.findByEmail(email).orElseThrow(() -> new BadRequestException("User not found"));
        return ResponseEntity.ok().body(UserDto.builder().id(user.getId()).email(user.getUsername()).role(user.getRole()).build());
    }

    @Override
    @Transactional(readOnly = true)
    public ResponseEntity<SigninResponseDto> refresh(String refreshToken) {
        refreshToken = SecurityCipher.decrypt(refreshToken);
        if (!jwtTokenUtil.validateToken(refreshToken)) {
            throw new IllegalArgumentException("Refresh Token is invalid!");
        }

        User user = userRepository.findByEmail(jwtTokenUtil.getUsernameFromToken(refreshToken))
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        Token newAccessToken = jwtTokenUtil.generateAccessToken(user);
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add(HttpHeaders.SET_COOKIE, cookieUtil.createAccessTokenCookie(newAccessToken.getTokenValue(),
                newAccessToken.getDuration()).toString());

        SigninResponseDto loginResponse = new SigninResponseDto(SigninResponseDto.SuccessFailure.SUCCESS,
                AUTH_SUCCESSFUL_MSG);
        return ResponseEntity.ok().headers(responseHeaders).body(loginResponse);
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
