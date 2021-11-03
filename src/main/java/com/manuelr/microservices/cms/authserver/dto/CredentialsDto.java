package com.manuelr.microservices.cms.authserver.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@ToString
public class CredentialsDto {
    private String email;
    private String password;
}
