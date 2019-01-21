package br.com.lbcoutinho.auth.security.config;

import br.com.lbcoutinho.auth.security.filter.JWTAuthenticationFilter;
import br.com.lbcoutinho.auth.security.filter.JWTAuthorizationFilter;
import br.com.lbcoutinho.auth.security.handler.JWTAuthenticationHandler;
import br.com.lbcoutinho.auth.security.service.UserServiceAuthenticationProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * Routes starting with /app are authenticated with Basic Authentication
     */
    @Configuration
    @Order(1)
    @Slf4j
    static class BasicWebSecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            log.trace("BasicWebSecurityConfig.configure(HttpSecurity)");
            http
                    .antMatcher("/app/**")
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
            manager.createUser(User.withUsername("admin").password("$2a$10$Fiz8ZUjSvlZpgATT2TZpsOkXaLS.9IUrplcQUlMqw49dsv/MUXhDq").roles("ADMIN").build());
            return manager;
        }
    }

    /**
     * Routes /login and any other are handled by this configuration
     */
    @Configuration
    @Slf4j
    @Order(2)
    static class JWTWebSecurityConfig extends WebSecurityConfigurerAdapter {

        private UserServiceAuthenticationProvider userServiceAuthenticationProvider;
        private JWTAuthenticationHandler jwtAuthenticationHandler;
        private ObjectMapper objectMapper;

        @Autowired
        public JWTWebSecurityConfig(UserServiceAuthenticationProvider userServiceAuthenticationProvider, JWTAuthenticationHandler jwtAuthenticationHandler, ObjectMapper objectMapper) {
            this.userServiceAuthenticationProvider = userServiceAuthenticationProvider;
            this.jwtAuthenticationHandler = jwtAuthenticationHandler;
            this.objectMapper = objectMapper;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            log.trace("JWTWebSecurityConfig.configure(HttpSecurity)");
            http
                    // Enable CORS - by default uses a Bean by the name of corsConfigurationSource
                    .cors().and()
                    // Disable CSRF
                    .csrf().disable()
                    .authorizeRequests()
                    // Permit POST to /login
                    .antMatchers(HttpMethod.POST, "/login").permitAll() // TODO define /login route on config file and reuse
                    // Any other request must be authorized using JWT
                    .anyRequest().authenticated()
                    .and()
                    .addFilter(jwtAuthenticationFilter())
                    .addFilter(jwtAuthorizationFilter())
                    // Disables session creation of Spring Security
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        }

        /**
         * Configure {@link AuthenticationManagerBuilder} to use the {@link UserServiceAuthenticationProvider} to authenticate the users.
         */
        @Override
        protected void configure(AuthenticationManagerBuilder auth) {
            log.trace("JWTWebSecurityConfig.configure(AuthenticationManagerBuilder)");
            auth.authenticationProvider(userServiceAuthenticationProvider);
        }

        private JWTAuthenticationFilter jwtAuthenticationFilter() throws Exception {
            return new JWTAuthenticationFilter(authenticationManager(), jwtAuthenticationHandler, objectMapper);
        }

        private JWTAuthorizationFilter jwtAuthorizationFilter() throws Exception {
            return new JWTAuthorizationFilter(authenticationManager(), objectMapper);
        }
    }

    /**
     * Allow/restrict CORS support. <br>
     * "/**" permits request from any source.
     */
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.applyPermitDefaultValues();

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

}
