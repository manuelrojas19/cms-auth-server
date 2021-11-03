package com.manuelr.microservices.cms.authserver.dto;

import com.manuelr.microservices.cms.authserver.entity.Role;
import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDto {
    private Long id;
    private String email;
    private Role role;
}
