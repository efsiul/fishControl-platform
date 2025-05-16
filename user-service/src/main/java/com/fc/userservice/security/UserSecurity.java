package com.fc.userservice.security;

import com.fc.userservice.models.UserEntity;
import com.fc.userservice.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component("userSecurity")
public class UserSecurity {

    @Autowired
    private UserRepository userRepository;

    public boolean isCurrentUser(Long userId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentUsername = authentication.getName();

        UserEntity user = userRepository.findById(userId).orElse(null);

        return user != null && user.getUsername().equals(currentUsername);
    }
}