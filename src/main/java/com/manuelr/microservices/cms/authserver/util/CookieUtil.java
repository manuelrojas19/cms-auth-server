package com.manuelr.microservices.cms.authserver.util;

import com.manuelr.cms.commons.utils.SecurityCipher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;


@Component
public class CookieUtil {
    @Value("${authentication-dev.auth.accessTokenCookieName}")
    private String accessTokenCookieName;

    @Value("${authentication-dev.auth.refreshTokenCookieName}")
    private String refreshTokenCookieName;

    public HttpCookie createAccessTokenCookie(String token, Long duration) {
        String encryptedToken = SecurityCipher.encrypt(token);
        if (encryptedToken == null) throw new AssertionError();
        return ResponseCookie.from(accessTokenCookieName, encryptedToken)
                .maxAge(duration)
                .httpOnly(true)
                .path("/")
                .build();
    }

    public HttpCookie createRefreshTokenCookie(String token, Long duration) {
        String encryptedToken = SecurityCipher.encrypt(token);
        if (encryptedToken == null) throw new AssertionError();
        return ResponseCookie.from(refreshTokenCookieName, encryptedToken)
                .maxAge(duration)
                .httpOnly(true)
                .path("/")
                .build();
    }

    public HttpCookie deleteAccessTokenCookie() {
        return ResponseCookie.from(accessTokenCookieName, "")
                .maxAge(0)
                .httpOnly(true)
                .path("/").build();
    }

    public HttpCookie deleteRefreshTokenCookie() {
        return ResponseCookie.from(refreshTokenCookieName, "")
                .maxAge(0)
                .httpOnly(true)
                .path("/").build();
    }
}
