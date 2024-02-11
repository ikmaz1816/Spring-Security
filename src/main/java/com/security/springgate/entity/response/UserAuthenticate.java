package com.security.springgate.entity.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UserAuthenticate {
    private String email;

    private String password;
}
