package com.security.springgate.controller;

import com.security.springgate.entity.response.Response;
import com.security.springgate.entity.response.UserAuthenticate;
import com.security.springgate.entity.response.UserRequest;
import com.security.springgate.service.AuthenticationService;
import lombok.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/register")
public class RegisterController {

    @Autowired
    private AuthenticationService authenticationService;

    @PostMapping("/")
    public ResponseEntity<Response> register(@NonNull @RequestBody UserRequest request)
    {
       Response response= authenticationService.getResponse(request);
       return ResponseEntity.ok(response);
    }

    @PostMapping("/authenticate")
    public ResponseEntity<Response> authenticate(@NonNull @RequestBody UserAuthenticate authenticate)
    {
        Response response= authenticationService.getAuthenticated(authenticate);
        return ResponseEntity.ok(response);
    }
}
