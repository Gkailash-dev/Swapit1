package com.example.product;

import com.example.product.Model.User;
import com.example.product.repository.Userrepo;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

@Component
public class CustomOAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final Userrepo userrepo;

    public CustomOAuth2SuccessHandler(Userrepo userrepo) {
        this.userrepo = userrepo;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String name = oAuth2User.getAttribute("name");
        String email = oAuth2User.getAttribute("email");

        // ✅ Check for existing user
        User user = userrepo.findByEmail(email);
        String message;

        if (user == null) {
            // First-time login → create new user
            user = new User();
            user.setUsername(name);
            user.setEmail(email);
            user.setRole("ROLE_USER");
            userrepo.save(user);
            message = "New user created";
            System.out.println("✅ Created new user: " + email);
        } else {
            // Returning user → use existing data
            message = "Welcome back!";
            System.out.println("👋 Existing user logged in: " + email);
        }

        // ✅ Set authentication context
        Authentication auth = new UsernamePasswordAuthenticationToken(
                user, null,
                Collections.singletonList(new SimpleGrantedAuthority(user.getRole()))
        );
        SecurityContextHolder.getContext().setAuthentication(auth);

        // ✅ Redirect safely
        if ("ROLE_ADMIN".equals(user.getRole())) {
            response.sendRedirect("/admin/dashboard");
        } else {
            response.sendRedirect("/user/user_product?message=" +
                    URLEncoder.encode(message, StandardCharsets.UTF_8));
        }
    }
}
