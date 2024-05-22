package com.hai.tran.spring.security.jwt.security.services;

import com.hai.tran.spring.security.jwt.exception.TokenRefreshException;
import com.hai.tran.spring.security.jwt.models.RefreshToken;
import com.hai.tran.spring.security.jwt.models.User;
import com.hai.tran.spring.security.jwt.repository.RefreshTokenRepository;
import com.hai.tran.spring.security.jwt.repository.UserRepository;
import com.hai.tran.spring.security.jwt.security.jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

@Service
public class RefreshTokenService {
  @Value("${app.jwtRfExp}")
  private Long refreshTokenDurationMs;

  @Autowired
  private RefreshTokenRepository refreshTokenRepository;

  @Autowired
  private UserRepository userRepository;

  @Autowired
  private JwtUtils jwtUtils;

  public Optional<RefreshToken> findByToken(String token) {
    return refreshTokenRepository.findByToken(token);
  }

  public RefreshToken createRefreshToken(Long userId,String jwt) {
    RefreshToken refreshToken = new RefreshToken();
    User user = userRepository.findById(userId).get();
    refreshToken.setUser(user);
    refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
    refreshToken.setToken(jwt);

    refreshToken = refreshTokenRepository.save(refreshToken);
    return refreshToken;
  }


  public RefreshToken verifyExpiration(RefreshToken token) {
    if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
      refreshTokenRepository.delete(token);
      throw new TokenRefreshException(token.getToken(), "Refresh token was expired. Please make a new signin request");
    }

    return token;
  }

  @Transactional
  public int deleteByUserId(Long userId) {
    User user = userRepository.findById(userId).get();
    return refreshTokenRepository.deleteByUser(user);
  }
}
