package cl.perfulandia.authentication.service;

import cl.perfulandia.authentication.dto.LoginRequest;
import cl.perfulandia.authentication.dto.LoginResponse;
import cl.perfulandia.authentication.model.User;
import cl.perfulandia.authentication.repository.UserRepository;
import cl.perfulandia.authentication.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    /**
     * Authenticates the user and returns a JWT if successful.
     */
    public LoginResponse authenticate(LoginRequest request) {
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("Invalid credentials"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid credentials");
        }

        String token = jwtUtil.generateToken(user.getUsername(), user.getRole());
        return new LoginResponse(token);
    }
}

