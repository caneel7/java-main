package com.caneel.main.security;

import com.caneel.main.models.User;
import com.caneel.main.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

@Component
public class AuthProvider {

    @Autowired
    private UserRepository userRepository;

    public User getUser() throws Exception
    {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if(auth == null || !(auth.getPrincipal() instanceof String))
        {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Invalid Or Expired Token");
        }
        String id = auth.getPrincipal().toString();
        if(id == null)
        {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,"InValid Or Expired Token");
        }
        Optional<User> foundUser = userRepository.findOneById(id);
        if(foundUser == null)
        {
            new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Cannot Find User");
        }
        return foundUser.get();
    }

}

