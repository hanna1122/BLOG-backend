package com.example.blog.dto;

import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import org.springframework.web.multipart.MultipartFile;

@Data
public class BoardPostRequest {
    private Long boardId;
    private String title;
    private String content;
    private Long regId;
    private String type;

    private MultipartFile[] files;

}
