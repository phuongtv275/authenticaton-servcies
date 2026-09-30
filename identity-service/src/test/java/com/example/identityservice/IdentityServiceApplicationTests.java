package com.example.identityservice;

import com.example.identityservice.models.constants.RoleName;
import com.example.identityservice.models.entities.Role;
import com.example.identityservice.models.entities.User;
import com.example.identityservice.security.jwt.JwtUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Set;

@SpringBootTest
class IdentityServiceApplicationTests {

    @Autowired
    private JwtUtils jwtUtils;

    @Test
    void contextLoads() {
        Assertions.assertNotNull(jwtUtils);
    }

    @Test
    void testGenerateToken() {
        User user = User.builder()
                .username("john_doe")
                .roles(Set.of(Role.builder().roleName(RoleName.ROLE_USER).build()))
                .build();
        String token = jwtUtils.generateToken(user);
        Assertions.assertNotNull(token);
        Assertions.assertFalse(token.isEmpty());
    }
}
