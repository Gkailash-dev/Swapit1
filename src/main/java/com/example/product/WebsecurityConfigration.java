package com.example.product;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.aspectj.EnableSpringConfigured;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableSpringConfigured
public class WebsecurityConfigration {
    private final UserDetailsService userDetailsService;

    public WebsecurityConfigration(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public static SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .authorizeHttpRequests(r -> r
                        .requestMatchers("/register","/login","/admin/login","/","/create_user","/user/login","/Access_by_customer_product","/images/{filename:.+}","/product/search").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/user/**").hasRole("USER")

                        .anyRequest().authenticated()

                )


                .formLogin(form -> form
                        .loginPage("/") // Spring will redirect here, but we’ll override with controllers
                        .loginProcessingUrl("/login") // both forms submit here
                        .successHandler((request, response, authentication) -> {
                            if (authentication.getAuthorities().toString().contains("ADMIN")) {
                                response.sendRedirect("/admin/dashboard");
                            } else {
                                response.sendRedirect("/user/dashboard");
                            }
                        })
                        .failureUrl("/login?error=true")
                        .permitAll()
                )


                 .csrf(csrf->csrf.disable());



                                          // allow everyone to see login page
        return httpSecurity.build();
    }
  @Bean
    public AuthenticationProvider authenticationProvider(){
      DaoAuthenticationProvider provider=new DaoAuthenticationProvider();
      provider.setUserDetailsService(userDetailsService);
      provider.setPasswordEncoder(bCryptPasswordEncoder());
      return provider;
  }
  @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
  }

  // authenticatio

}
