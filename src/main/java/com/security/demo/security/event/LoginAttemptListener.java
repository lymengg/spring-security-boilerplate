package com.security.demo.security.event;

import com.security.demo.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
@Transactional
public class LoginAttemptListener {

    private final UserRepository userRepository;

    public LoginAttemptListener(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @EventListener
    public void handleAuthenticationSuccess(AuthenticationSuccessEvent event) {
        String username = event.getAuthentication().getName();
        userRepository.findByUsername(username).ifPresent(user -> {
            user.resetFailedAttempts();
            userRepository.save(user);
        });
    }

    @EventListener
    public void handleAuthenticationFailure(AbstractAuthenticationFailureEvent event) {
        String username = event.getAuthentication().getName();
        userRepository.findByUsername(username).ifPresent(user -> {
            user.incrementFailedAttempts();
            userRepository.save(user);
        });
    }
}
