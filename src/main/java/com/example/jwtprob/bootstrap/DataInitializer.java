package com.example.jwtprob.bootstrap;

import com.example.jwtprob.user.Role;
import com.example.jwtprob.user.UserAccount;
import com.example.jwtprob.user.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

@Configuration
public class DataInitializer {

    @Bean
    CommandLineRunner initUsers(UserRepository userRepository, PasswordEncoder encoder) {
        return args -> {
            // GUEST 계정
            if (!userRepository.existsByUsername("guest")) {
                userRepository.save(new UserAccount("guest", encoder.encode("guest"), Set.of(Role.ROLE_GUEST)));
            }

            // USER 계정
            if (!userRepository.existsByUsername("user")) {
                userRepository.save(new UserAccount("user", encoder.encode("user"), Set.of(Role.ROLE_USER)));
            }

            // DEV 계정
            if (!userRepository.existsByUsername("dev")) {
                userRepository.save(new UserAccount("dev", encoder.encode("dev"), Set.of(Role.ROLE_DEV)));
            }

            // MANAGER 계정
            if (!userRepository.existsByUsername("manager")) {
                userRepository.save(new UserAccount("manager", encoder.encode("manager"), Set.of(Role.ROLE_MANAGER)));
            }

            // ADMIN 계정
            if (!userRepository.existsByUsername("admin")) {
                userRepository.save(new UserAccount("admin", encoder.encode("admin"), Set.of(Role.ROLE_ADMIN)));
            }

            // SUPER_ADMIN 계정
            if (!userRepository.existsByUsername("superadmin")) {
                userRepository.save(
                        new UserAccount("superadmin", encoder.encode("superadmin"), Set.of(Role.ROLE_SUPER_ADMIN)));
            }
        };
    }
}
