package com.galapea.belajar.springsecoauth2jwt.controller;

import com.galapea.belajar.springsecoauth2jwt.config.SecurityConfig;
import com.galapea.belajar.springsecoauth2jwt.service.TokenService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

@WebMvcTest({HomeController.class, AuthController.class})
@Import({SecurityConfig.class, TokenService.class})
public class HomeControllerTest {

    @Autowired
    MockMvc mvc;

    @Test
    void rootWhenUnauthenticatedThen401() throws Exception {
        this.mvc.perform(MockMvcRequestBuilders.get("/"))
                .andExpect(MockMvcResultMatchers.status().isUnauthorized());
    }

    @Test
    @WithMockUser
    void rootWithMockUserStatusIsOk() throws Exception {
        this.mvc.perform(MockMvcRequestBuilders.get("/"))
                .andExpect(MockMvcResultMatchers.status().isOk());
    }

    @Test
    void rootWithAuthenticatedThenReturnSuccess() throws Exception {
        MvcResult result = this.mvc.perform(MockMvcRequestBuilders.post("/token")
                        .with(SecurityMockMvcRequestPostProcessors.httpBasic("nama", "pass")))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andReturn();
        String token = result.getResponse().getContentAsString();
        this.mvc.perform(MockMvcRequestBuilders.get("/")
                        .header("Authorization", "Bearer " + token))
                .andExpect(MockMvcResultMatchers.content().string("Hello, nama. Authorities: [SCOPE_read]"));
    }
}
