package com.example.blog.dto;

import lombok.Data;

import javax.validation.constraints.NotNull;

@Data
public class UserDelRequest {

    @NotNull
    private Long userId;
}
