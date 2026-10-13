package com.rikkei.microservice.identity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rikkei.microservice.identity.config.TestRedisConfiguration;
import com.rikkei.microservice.identity.dto.LoginRequest;
import com.rikkei.microservice.identity.dto.RegisterRequest;
import com.rikkei.microservice.identity.entity.RefreshToken;
import com.rikkei.microservice.identity.repository.RefreshTokenRepository;
import com.rikkei.microservice.identity.repository.UserRepository;
import com.rikkei.microservice.identity.security.JwtUtils;
import com.rikkei.microservice.identity.service.BlacklistTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestRedisConfiguration.class)
public class AuthIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private BlacklistTokenService blacklistTokenService;

    @BeforeEach
    void setUp() {
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    void testRegisterAndLoginReturnsBothTokens() throws Exception {
        RegisterRequest registerRequest = RegisterRequest.builder()
                .username("testuser")
                .email("testuser@example.com")
                .password("password123")
                .roles(Set.of("USER"))
                .build();

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isOk());

        LoginRequest loginRequest = LoginRequest.builder()
                .username("testuser")
                .password("password123")
                .build();

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.username").value("testuser"))
                .andReturn();

        String responseContent = result.getResponse().getContentAsString();
        String accessToken = objectMapper.readTree(responseContent).get("accessToken").asText();
        String refreshTokenString = objectMapper.readTree(responseContent).get("refreshToken").asText();

        // 1. Verify Access Token
        assertThat(jwtUtils.validateJwtToken(accessToken)).isTrue();
        assertThat(jwtUtils.getUsernameFromJwtToken(accessToken)).isEqualTo("testuser");
        assertThat(jwtUtils.getJtiFromJwtToken(accessToken)).isNotNull();

        // 2. Verify Refresh Token is persisted in DB
        Optional<RefreshToken> tokenInDb = refreshTokenRepository.findByToken(refreshTokenString);
        assertThat(tokenInDb).isPresent();
        assertThat(tokenInDb.get().getUser().getUsername()).isEqualTo("testuser");
        assertThat(tokenInDb.get().getExpiryDate()).isAfter(java.time.Instant.now());
    }

    @Test
    void testLogoutBlacklistsAccessTokenAndRevokesAccess() throws Exception {
        RegisterRequest registerRequest = RegisterRequest.builder()
                .username("logoutuser")
                .email("logoutuser@example.com")
                .password("password123")
                .roles(Set.of("USER"))
                .build();

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isOk());

        LoginRequest loginRequest = LoginRequest.builder()
                .username("logoutuser")
                .password("password123")
                .build();

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String responseContent = result.getResponse().getContentAsString();
        String accessToken = objectMapper.readTree(responseContent).get("accessToken").asText();
        String refreshTokenString = objectMapper.readTree(responseContent).get("refreshToken").asText();
        String jti = jwtUtils.getJtiFromJwtToken(accessToken);

        // Access protected resource before logout
        mockMvc.perform(get("/api/test/user")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk());

        // Perform logout
        mockMvc.perform(post("/api/auth/logout")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Log out successful!"));

        // Verify token is in blacklist
        assertThat(blacklistTokenService.isBlacklisted(jti)).isTrue();

        // Verify Refresh Token was deleted from DB
        Optional<RefreshToken> tokenInDb = refreshTokenRepository.findByToken(refreshTokenString);
        assertThat(tokenInDb).isEmpty();

        // Verify accessing protected resource with revoked token is denied
        mockMvc.perform(get("/api/test/user")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isUnauthorized());
    }
}
