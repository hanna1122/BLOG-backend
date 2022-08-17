package com.example.blog.service;


import com.example.blog.dto.CommentRequest;
import com.example.blog.model.Board;
import com.example.blog.model.Comment;
import com.example.blog.model.User;
import com.example.blog.repository.CommentRepository;
import com.example.blog.repository.UserRepository;

import java.io.IOException;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class CommentService {

    private final CommentRepository commentRepository;
    private final UserRepository userRepository;

    public List<Comment> getCommentList(Long boardId){
        return commentRepository.findByBoard_BoardId(boardId);
    }

    /**

     * @Method Name : commentPost
     * @Method 설명 : 댓글등록
     * @param commentRequest
     * @param email
     */
    public Comment commentPost(CommentRequest commentRequest, String email){
        Optional<User> optionalUser = userRepository.findByEmailAndUseYn(email, "Y");

        if (optionalUser.isPresent()) {
            Comment comment = new Comment().builder()
                .board(Board.builder().boardId(commentRequest.getBoardId()).build())
                .regId(optionalUser.get())
                .content(commentRequest.getContent())
                .depth(commentRequest.getDepth())
                .upperId(commentRequest.getUpperId())
                .build();
            return commentRepository.save(comment);
        }

        return null;
    }

    /**

     * @Method Name : commentUpdate
     * @Method 설명 : 댓글수정
     * @param commentRequest
     */
    public Comment commentUpdate(CommentRequest commentRequest){
        Optional<Comment> optionalComment = commentRepository.findById(commentRequest.getCommentId());

        if (optionalComment.isPresent()) {

            Comment comment = optionalComment.get();
            comment.setContent(commentRequest.getContent());
            return commentRepository.save(comment);
        }

        return null;
    }

    /**

     * @Method Name : commentDelete
     * @Method 설명 : 댓글삭제
     * @param commentId
     */
    public void commentDelete(Long commentId){
        commentRepository.deleteById(commentId);
    }
}
