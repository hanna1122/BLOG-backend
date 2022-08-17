package com.example.blog.jwt;

import com.example.blog.model.User;
import com.example.blog.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;


@Service
public class JwtUserDetailsService {
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepository;

    public User authenticateByEmailAndPassword(String email, String password) {
        Optional<User> User = userRepository.findByEmailAndUseYn(email, "Y");

        if(User.isPresent()){
            User member = User.get();
            if(!passwordEncoder.matches(password, member.getPassword())) {
                throw new BadCredentialsException("Password not matched");
            }

            return member;
        }else{
            return null;
        }

    }
}
