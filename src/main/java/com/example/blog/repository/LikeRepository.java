package com.example.blog.repository;

import com.example.blog.model.Board;
import com.example.blog.model.LikeBoard;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface LikeRepository extends JpaRepository<LikeBoard, Long> {

}
