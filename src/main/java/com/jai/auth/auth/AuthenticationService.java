package com.jai.auth.auth;

import com.jai.auth.config.JwtService;
import com.jai.auth.user.Role;
import com.jai.auth.user.User;
import com.jai.auth.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest reqBody) {
        User user = User.builder().firstname(reqBody.getFirstname())
                .lastname(reqBody.getLastname())
                .email(reqBody.getEmail())
                .password(passwordEncoder.encode(reqBody.getPassword()))
                .role(Role.USER)
                .build();
        userRepository.save(user);

        String jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest reqBody) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(reqBody.getEmail(), reqBody.getPassword())
        );

        User user = userRepository.findByEmail(reqBody.getEmail())
                .orElseThrow();

        String jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

}
