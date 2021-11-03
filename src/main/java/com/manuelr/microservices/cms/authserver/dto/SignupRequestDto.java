package com.manuelr.microservices.cms.authserver.dto;

import com.manuelr.microservices.cms.authserver.entity.Role;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SignupRequestDto {
    private String email;
    private String password;
    private Role role;
}
