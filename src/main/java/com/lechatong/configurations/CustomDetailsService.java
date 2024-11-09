package com.lechatong.configurations;

import com.lechatong.models.LcuUser;
import com.lechatong.repositories.LcuUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class CustomDetailsService implements UserDetailsService {

    @Autowired
    private LcuUserRepository lcuUserRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        LcuUser user = lcuUserRepository.findByUsername(username);
        return new User(user.getUsername(), user.getPassword(), getGrantedAuthorities(user.getRole()));
    }

    private List<GrantedAuthority> getGrantedAuthorities(String role){
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_" + role));

        return authorities;
    }
}