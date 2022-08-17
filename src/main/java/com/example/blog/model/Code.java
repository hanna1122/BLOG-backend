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
public class Code {

    @Id
    @GeneratedValue(strategy= GenerationType.IDENTITY)
    private Long codeId;

    @Column(length = 100)
    private String codeName;

    @Column(length = 20)
    private String type;

}
