package br.com.lbcoutinho.auth.security.config;

import br.com.lbcoutinho.auth.security.filter.JWTAuthenticationFilter;
import br.com.lbcoutinho.auth.security.filter.JWTAuthorizationFilter;
import br.com.lbcoutinho.auth.security.service.UserAuthenticationProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static br.com.lbcoutinho.auth.model.Authority.ADMIN;
import static br.com.lbcoutinho.auth.security.util.SecurityConstants.ENCODED_PASSWORD_12345;

@EnableWebSecurity
public class WebSecurityConfig {

    /**
     * Routes containing /basic are authenticated with Basic Authentication.
     */
    @Configuration
    @Order(1)
    @Slf4j
    static class BasicWebSecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            log.trace("BasicWebSecurityConfig.configure(HttpSecurity)");
            http
                    .antMatcher("/basic/**")
                    .authorizeRequests()
                    .anyRequest().authenticated()
                    .and()
                    .httpBasic();
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.userDetailsService(userDetailsService());
        }

        @Override
        protected UserDetailsService userDetailsService() {
            InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
            manager.createUser(User.withUsername("user1").password(ENCODED_PASSWORD_12345).roles("USER").build());
            return manager;
        }
    }

    /**
     * Any other route (including /login) is handled by this configuration and authenticated with Bearer Authentication.<br>
     * /login route is not going to require Bearer Authentication because the {@link JWTAuthenticationFilter} is setup before the {@link JWTAuthorizationFilter}.<br>
     * {@link JWTAuthenticationFilter} is going to capture the /login requests, block the Security Chain from proceeding and authenticate the user.
     */
    @Configuration
    @Order(2)
    @Slf4j
    static class JWTWebSecurityConfig extends WebSecurityConfigurerAdapter {

        private UserAuthenticationProvider userAuthenticationProvider;
        private ObjectMapper objectMapper;

        @Autowired
        public JWTWebSecurityConfig(UserAuthenticationProvider userAuthenticationProvider, ObjectMapper objectMapper) {
            this.userAuthenticationProvider = userAuthenticationProvider;
            this.objectMapper = objectMapper;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            log.trace("JWTWebSecurityConfig.configure(HttpSecurity)");
            http
                    // Disable CSRF
                    .csrf().disable()
                    .authorizeRequests()
                    // Permit POST to /login
                    .antMatchers(HttpMethod.POST, "/login").permitAll()
                    // Any routes containing /admin are going to require ADMIN authority
                    .antMatchers("/admin/**").hasAuthority(ADMIN.getAuthority())
                    // Any request will require authentication.
                    // /login route is not going to require authentication because it's setup with permitAll
                    .anyRequest().authenticated()
                    .and()
                    // Filter that captures the /login requests
                    .addFilter(jwtAuthenticationFilter())
                    // Filter responsible for validating the JWT token and setting the SecurityContext to indicate that the user is authenticated
                    .addFilterAfter(jwtAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class)
                    // Disables session creation of Spring Security
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        }

        /**
         * Configure {@link AuthenticationManagerBuilder} to use the {@link UserAuthenticationProvider} to authenticate the users.
         */
        @Override
        protected void configure(AuthenticationManagerBuilder auth) {
            log.trace("JWTWebSecurityConfig.configure(AuthenticationManagerBuilder)");
            auth.authenticationProvider(userAuthenticationProvider);
        }

        private JWTAuthenticationFilter jwtAuthenticationFilter() throws Exception {
            return new JWTAuthenticationFilter(authenticationManager(), objectMapper);
        }

        private JWTAuthorizationFilter jwtAuthorizationFilter() {
            return new JWTAuthorizationFilter(objectMapper);
        }
    }

}
