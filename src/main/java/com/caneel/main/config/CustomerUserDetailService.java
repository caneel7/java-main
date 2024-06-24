package com.caneel.main.config;

import com.caneel.main.models.User;
import com.caneel.main.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomerUserDetailService implements UserDetailsService {


    private final UserRepository userRepository;

    @Autowired
    public CustomerUserDetailService(UserRepository userRepository)
    {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
    {
        User user = userRepository.findOneByUsername(username).orElseThrow(()-> new UsernameNotFoundException("Cannot Find User"));
        return new org.springframework.security.core.userdetails.User(user.getId(),user.getPassword(),null);
    }

    public UserDetails loadUserById(String id) throws UsernameNotFoundException
    {
        User user = userRepository.findOneById(id).orElseThrow(()-> new UsernameNotFoundException("Cannot Find User"));
        return new org.springframework.security.core.userdetails.User(user.getId(),user.getPassword(),null);
    }

}
