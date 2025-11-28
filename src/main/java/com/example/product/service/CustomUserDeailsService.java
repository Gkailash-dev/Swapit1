package com.example.product.service;

import com.example.product.Model.User;
import com.example.product.repository.Userrepo;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Objects;
@Component
public class CustomUserDeailsService implements UserDetailsService {
    private  final Userrepo userrepo;

    public CustomUserDeailsService(Userrepo userrepo) {
        this.userrepo = userrepo;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user=  userrepo.findByUsername(username);
        if (Objects.isNull(user)){
            throw  new UsernameNotFoundException("user not foud");

        }
        return  new CustomUserDetails(user);
    }

}
