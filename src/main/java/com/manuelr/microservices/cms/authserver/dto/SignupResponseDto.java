package com.manuelr.microservices.cms.authserver.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class SignupResponseDto {
    private SignupResponseDto.SuccessFailure status;
    private String message;

    public enum SuccessFailure {
        SUCCESS, FAILURE
    }
}
