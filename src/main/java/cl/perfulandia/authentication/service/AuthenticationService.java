package cl.perfulandia.authentication.service;

import cl.perfulandia.authentication.dto.LoginRequest;
import cl.perfulandia.authentication.dto.LoginResponse;
import cl.perfulandia.authentication.dto.UserDto;
import cl.perfulandia.authentication.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.security.crypto.password.PasswordEncoder;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final RestTemplate restTemplate;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    // URL base de Users Service
    private final String usersBaseUrl = "http://localhost:8082/users";

    public LoginResponse authenticate(LoginRequest request) {
        UserDto user;
        try {
            user = restTemplate.getForObject(
                    usersBaseUrl + "/username/{username}",
                    UserDto.class,
                    request.getUsername()
            );
        } catch (HttpClientErrorException.NotFound ex) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Usuario no existe");
        }

        if (user == null || !passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Credenciales inválidas");
        }

        String token = jwtUtil.generateToken(user.getUsername(), user.getRole());
        return new LoginResponse(token);
    }
}
