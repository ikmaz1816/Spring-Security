package com.security.springgate.service;

import com.security.springgate.entity.Role;
import com.security.springgate.entity.User;
import com.security.springgate.entity.response.Response;
import com.security.springgate.entity.response.UserAuthenticate;
import com.security.springgate.entity.response.UserRequest;
import com.security.springgate.filter.JwtService;
import com.security.springgate.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    @Autowired
    private final PasswordEncoder passwordEncoder;
    @Autowired
    private final JwtService jwtService;

    @Autowired
    private final AuthenticationManager manager;

    @Autowired
    private final UserRepository userRepository;
    public Response getResponse(UserRequest request)
    {
        var user= User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .role(Role.USER)
                .build();
        UserDetails userDetails=userRepository.save(user);
        String jwt=jwtService.generateTokenWithoutClaims(userDetails);
        return Response.builder().token(jwt).build();

    }

    public Response getAuthenticated(UserAuthenticate authenticate) {
        manager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authenticate.getEmail(),
                        authenticate.getPassword()
                )
        );
        UserDetails userDetails=this.userRepository.findByEmail(authenticate.getEmail()).get();
        String token = jwtService.generateTokenWithoutClaims(userDetails);
        return Response.builder().token(token).build();

    }
}
