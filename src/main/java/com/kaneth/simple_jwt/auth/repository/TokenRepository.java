package com.kaneth.simple_jwt.auth.repository;

import com.kaneth.simple_jwt.auth.entity.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token, Long> {

    @Query(
            "select t from Token t " +
            "where t.user.userId = :userId " +
            "and (t.revoked = false or t.expired = false)"
    )
    public List<Token> findValidTokensByUserId(Long userId);

    public Optional<Token> findByToken (String token);
}
