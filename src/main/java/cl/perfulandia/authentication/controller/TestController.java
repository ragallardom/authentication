package cl.perfulandia.authentication.controller;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.security.Principal;

@RestController
public class TestController {

    @GetMapping("/hello")
    public String hello(Principal user) {
        // user.getName() vendrá del JWT
        return "Hello, " + user.getName();
    }
}

