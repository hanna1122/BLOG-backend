package com.example.blog.dto;

import lombok.Data;

@Data
public class ImageRequest {
    private Long imageId;
    private Long boardId;
    private String fileName;
    private String fileSrc;
    private String fileType;
}
