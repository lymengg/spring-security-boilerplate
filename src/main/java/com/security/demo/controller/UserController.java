package com.security.demo.controller;

import com.security.demo.dto.ApiResponse;
import com.security.demo.dto.UserResponse;
import com.security.demo.service.impl.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserResponse>> getCurrentUser(Authentication authentication) {
        return ResponseEntity.ok(ApiResponse.success(userService.getCurrentUser(authentication)));
    }
}
