package com.security.springgate.entity.response;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class UserRequest {
    private String firstname;
    private String lastname;

    private String email;

    private String password;
}

