package com.example.blog.dto;

import lombok.Data;

@Data
public class CommentRequest {
    private Long commentId;
    private Long boardId;
    private String content;
    private Integer depth;
    private Integer upperId;
}
