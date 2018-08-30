package com.service.auth.serviceauth.dto;

import com.service.auth.serviceauth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserDao extends JpaRepository<User, Long> {
    User findByUsername(String username);

}
