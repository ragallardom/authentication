package cl.perfulandia.authentication.controller;

import cl.perfulandia.authentication.dto.LoginRequest;
import cl.perfulandia.authentication.dto.LoginResponse;
import cl.perfulandia.authentication.service.AuthenticationService;
import cl.perfulandia.authentication.service.AuthenticationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @RequestBody @Valid LoginRequest request) {
        LoginResponse response = authenticationService.authenticate(request);
        return ResponseEntity.ok(response);
    }
}
