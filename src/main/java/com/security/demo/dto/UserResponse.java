package com.security.demo.dto;

import java.util.List;

public record UserResponse(String username, List<String> roles) {}
