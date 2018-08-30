package com.service.hi.servicehi.dto;

import com.service.hi.servicehi.entity.User;

public interface UserService {
    public User create(String username, String password);
}
