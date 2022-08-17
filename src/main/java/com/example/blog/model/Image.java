package com.example.blog.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Image {

    @Id
    @GeneratedValue(strategy= GenerationType.IDENTITY)
    private Long imageId;

    @ManyToOne
    @JoinColumn(name = "board_id")
    private Board boardId;

    private String fileName;

    private String fileSrc;

    @Column(length = 10)
    private String fileType;

}
