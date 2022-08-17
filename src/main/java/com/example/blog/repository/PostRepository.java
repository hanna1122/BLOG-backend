package com.example.blog.repository;

import com.example.blog.model.Board;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PostRepository extends JpaRepository<Board, Long> {


    List<Board> findByRegId(String regId);

}
