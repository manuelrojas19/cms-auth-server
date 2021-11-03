package com.manuelr.microservices.cms.authserver.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class SigninResponseDto {
    private SuccessFailure status;
    private String message;

    public enum SuccessFailure {
        SUCCESS, FAILURE
    }
}

