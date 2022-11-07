package com.galapea.belajar.combiningspringbootauth;

import com.galapea.belajar.combiningspringbootauth.auth.AuthService;
import com.galapea.belajar.combiningspringbootauth.auth.AuthServiceBasic;
import com.galapea.belajar.combiningspringbootauth.auth.AuthServiceJwt;
import com.galapea.belajar.combiningspringbootauth.auth.AuthServiceRedis;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Optional;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Slf4j
public class SecurityConfig {

    @Autowired
    private AuthServiceBasic authServiceBasic;
    @Autowired
    private AuthServiceJwt authServiceJwt;
    @Autowired
    private AuthServiceRedis authServiceRedis;
    @Value("${spring.websecurity.debug:false}")
    boolean webSecurityDebug;

    private final RequestMatcher rootUriMatcher =
            new AntPathRequestMatcher("/", HttpMethod.GET.name());
    private final RequestMatcher errorUriMatcher =
            new AntPathRequestMatcher("/error", HttpMethod.GET.name());
    private final RequestMatcher faviconUriMatcher =
            new AntPathRequestMatcher("/favicon.ico", HttpMethod.GET.name());
    private final RequestMatcher shouldNotFilterAuthMatcher = new AndRequestMatcher(List.of(
            new NegatedRequestMatcher(rootUriMatcher),
            new NegatedRequestMatcher(errorUriMatcher),
            new NegatedRequestMatcher(faviconUriMatcher)
    ));

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .addFilterAt(this::authenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(config -> {
                    config.antMatchers("/").permitAll();
                    config.antMatchers("/error").permitAll();
                    config.antMatchers("/favicon.ico").permitAll();
                    config.anyRequest().authenticated();
                })
                // Disable "JSESSIONID" cookies
                .sessionManagement(conf -> {
                    conf.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                })
                // Exception handling
                .exceptionHandling(conf -> {
                    conf.authenticationEntryPoint(this::authenticationFailedHandler);
                })
                .build();
    }

    private void authenticationFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws ServletException, IOException {
        /*
        exclude some url from custom-authentication
         */
        if (shouldNotFilterAuthMatcher.matches((HttpServletRequest) request)) {
            Optional<Authentication> authentication = this.authenticate((HttpServletRequest) request);
            authentication.ifPresent(SecurityContextHolder.getContext()::setAuthentication);
        }
        chain.doFilter(request, response);
    }

    private Optional<Authentication> authenticate(HttpServletRequest request) {
        List<AuthService> authServices = List.of(authServiceBasic, authServiceJwt, authServiceRedis);
        for (AuthService authService : authServices) {
            Optional<Authentication> authentication = authService.authenticate(request);
            if (authentication.isPresent()) {
                return authentication;
            }
        }
        return Optional.empty();
    }

    private void authenticationFailedHandler(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) {
        httpServletResponse.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Basic");
        httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.debug(webSecurityDebug);
    }

    @Bean
    public InMemoryUserDetailsManager users() {
        return new InMemoryUserDetailsManager(
                User.withUsername("user")
                        .password("{noop}pass")
                        .authorities("read")
                        .build()
        );
    }

}
