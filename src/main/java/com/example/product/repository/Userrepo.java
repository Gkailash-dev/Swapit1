package com.example.product.repository;

import com.example.product.Model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface Userrepo extends JpaRepository<User,Integer> {

   User findByUsername(String  username);

    String deleteById(int id);

    boolean existsByUsername(String username);
}
