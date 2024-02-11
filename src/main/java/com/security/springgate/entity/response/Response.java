package com.security.springgate.entity.response;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class Response {
    private  String token;
}
