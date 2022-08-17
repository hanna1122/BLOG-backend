package com.example.blog.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.ColumnDefault;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;

import javax.persistence.*;
import java.time.LocalDateTime;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@DynamicInsert
@DynamicUpdate
public class Board {

    @Id
    @GeneratedValue(strategy= GenerationType.IDENTITY)
    private Long boardId;
    private String title;

    @Column(length = 1000)
    private String content;

    @ManyToOne
    @JoinColumn(name = "reg_id")
    private User regId;

    @ColumnDefault("0")
    private Long hit;
    @Column(nullable=false, updatable = false)
    @CreationTimestamp
    private LocalDateTime regDt;

    @ManyToOne
    @JoinColumn(name = "mod_id")
    private User modId;

    @Column(insertable = false)
    private LocalDateTime modDt;

    @ManyToOne
    @JoinColumn(name = "type", referencedColumnName = "type")
    private Code type;
}
