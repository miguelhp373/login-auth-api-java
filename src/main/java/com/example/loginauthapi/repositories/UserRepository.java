package com.example.loginauthapi.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.loginauthapi.domain.user.User;

public interface UserRepository extends JpaRepository<User, String>{
    
    Optional<User> findByEmail(String email);

}
