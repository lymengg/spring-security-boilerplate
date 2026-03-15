package com.security.demo.security;


import com.security.demo.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Arrays;
import java.util.Collection;

public record CustomUserDetails(User userEntity) implements UserDetails {
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Arrays.stream(userEntity.getRoles().split(","))
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.trim()))
                .toList();
    }

    @Override public String getPassword() { return userEntity.getPassword(); }
    @Override public String getUsername() { return userEntity.getUsername(); }
    @Override public boolean isAccountNonExpired() { return userEntity.isAccountActive(); }
    @Override public boolean isAccountNonLocked() { return !userEntity.isLocked(); }
    @Override public boolean isCredentialsNonExpired() { return userEntity.isPasswordValid(); }
    @Override public boolean isEnabled() { return userEntity.isEnabled(); }
}
