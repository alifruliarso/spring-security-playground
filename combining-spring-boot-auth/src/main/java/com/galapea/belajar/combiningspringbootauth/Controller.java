package com.galapea.belajar.combiningspringbootauth;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

import static java.util.Map.entry;

@RestController
public class Controller {

    @GetMapping("/")
    Map<String, String> index(Authentication authentication) {
        return Map.ofEntries(
                entry("endpoint", "/")
        );
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    Map<String, String> user(Authentication authentication) {
        return Map.ofEntries(
                Map.entry("endpoint", "user"),
                Map.entry("actor", authentication.getName())
        );
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    Map<String, String> admin(Authentication authentication) {
        return Map.ofEntries(
                Map.entry("endpoint", "admin"),
                Map.entry("actor", authentication.getName())
        );
    }

    @GetMapping("/system")
    @PreAuthorize("hasRole('SYSTEM')")
    Map<String, String> system(Authentication authentication) {
        return Map.ofEntries(
                Map.entry("endpoint", "system"),
                Map.entry("actor", authentication.getName())
        );
    }
}
