package com.galapea.belajar.springsecoauth2jwt.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Optional;


@RestController
public class HomeController {

    @GetMapping
    public String home(Authentication authentication) {
        return "Hello, " + authentication.getName() + ". Authorities: " + authentication.getAuthorities();
    }

    @PreAuthorize("hasAuthority('SCOPE_read')")
    @GetMapping("/secure")
    public String secure() {
        return "This is secured";
    }
}
