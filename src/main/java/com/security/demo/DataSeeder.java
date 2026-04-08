package com.security.demo;

import com.security.demo.entity.User;
import com.security.demo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@Slf4j // Provides a 'log' variable for clean logging
@RequiredArgsConstructor
public class DataSeeder implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        // Only seed if the database is empty to avoid duplicates on restart
        if (userRepository.count() == 0) {

            log.info("Seeding initial security users...");

            User admin = User.builder()
                    .username("admin")
                    // CRITICAL: Always encode the password
                    .password(passwordEncoder.encode("admin123"))
                    .roles("ROLE_USER,ROLE_ADMIN")
                    .build();

            User user = User.builder()
                    .username("user")
                    .password(passwordEncoder.encode("user123"))
                    .roles("ROLE_USER")
                    .build();

            userRepository.save(admin);
            userRepository.save(user);

            log.info("Seeding complete. Admin password is 'admin123'");
        }
    }
}
