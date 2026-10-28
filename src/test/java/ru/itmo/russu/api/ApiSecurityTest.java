package ru.itmo.russu.api;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {"spring.datasource.url=jdbc:h2:mem:test;DB_CLOSE_DELAY=-1",
        "spring.jpa.hibernate.ddl-auto=create-drop"})
@AutoConfigureMockMvc
class ApiSecurityTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired UserRepository users;
    @Autowired PasswordEncoder passwords;
    @Autowired JwtEncoder encoder;
    String password;

    static String randomSecret() {
        byte[] bytes = new byte[48];
        new SecureRandom().nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }
    @DynamicPropertySource
    static void configuration(DynamicPropertyRegistry r) {
        String jwt = randomSecret();
        String db = randomSecret();
        r.add("app.jwt.secret", () -> jwt);
        r.add("spring.datasource.password", () -> db);
    }
    @BeforeEach void setup() { users.deleteAll(); password = randomSecret(); }

    void register(String login, String name) throws Exception {
        mvc.perform(post("/auth/register").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("login",login,"password",password,"displayName",name))))
                .andExpect(status().isCreated());
    }
    String login() throws Exception {
        var result = mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("login","alice","password",password))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(900)).andReturn();
        return json.readTree(result.getResponse().getContentAsString()).get("accessToken").asText();
    }
    @Test void registerLoginAndRead() throws Exception {
        register("alice", "Alice");
        mvc.perform(get("/api/data").header("Authorization", "Bearer " + login()))
                .andExpect(status().isOk()).andExpect(jsonPath("$[0].login").value("alice"))
                .andExpect(jsonPath("$[0].passwordHash").doesNotExist());
    }
    @Test void accessWithoutTokenIsDenied() throws Exception {
        mvc.perform(get("/api/data")).andExpect(status().isUnauthorized());
    }
    @Test void malformedTokenIsDenied() throws Exception {
        mvc.perform(get("/api/data").header("Authorization", "Bearer invalid.token.value"))
                .andExpect(status().isUnauthorized());
    }
    @Test void wrongPasswordIsDenied() throws Exception {
        register("alice", "Alice");
        mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("login","alice","password",randomSecret()))))
                .andExpect(status().isUnauthorized());
    }
    @Test void sqlInjectionDoesNotAuthenticate() throws Exception {
        register("alice", "Alice");
        mvc.perform(post("/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("login","' OR 1=1 --","password",password))))
                .andExpect(status().isUnauthorized());
        assertThat(users.count()).isEqualTo(1);
    }
    @Test void htmlIsEscapedInResponses() throws Exception {
        register("alice", "<script>alert(1)</script>");
        mvc.perform(get("/api/data").header("Authorization", "Bearer " + login()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].displayName").value("&lt;script&gt;alert(1)&lt;/script&gt;"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"));
    }
    @Test void passwordIsStoredAsSaltedBcrypt() throws Exception {
        register("alice", "Alice"); register("bob", "Bob");
        String a = users.findByLogin("alice").orElseThrow().getPasswordHash();
        String b = users.findByLogin("bob").orElseThrow().getPasswordHash();
        assertThat(a).startsWith("$2a$12$").isNotEqualTo(password).isNotEqualTo(b);
        assertThat(passwords.matches(password, a)).isTrue();
    }
    @Test void anotherUsersDataIsNotReturned() throws Exception {
        register("alice", "Alice"); register("bob", "Bob");
        mvc.perform(get("/api/data").header("Authorization", "Bearer " + login()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].login").value("alice"));
    }
    @Test void duplicateLoginIsRejected() throws Exception {
        register("alice", "Alice");
        mvc.perform(post("/auth/register").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("login","alice","password",password,"displayName","Other"))))
                .andExpect(status().isConflict());
    }
    @Test void shortPasswordIsRejected() throws Exception {
        mvc.perform(post("/auth/register").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("login","alice","password","short","displayName","Alice"))))
                .andExpect(status().isBadRequest());
    }
    @Test void oversizedUtf8PasswordIsRejected() throws Exception {
        mvc.perform(post("/auth/register").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("login","alice","password","я".repeat(40),"displayName","Alice"))))
                .andExpect(status().isBadRequest());
    }
    @Test void invalidJsonIsRejected() throws Exception {
        mvc.perform(post("/auth/register").contentType(MediaType.APPLICATION_JSON).content("{"))
                .andExpect(status().isBadRequest());
    }
    String signedToken(Instant exp, String audience, String issuer) {
        var claims = JwtClaimsSet.builder().issuer(issuer).subject("1")
                .issuedAt(Instant.now().minusSeconds(1000));
        if (audience != null) claims.audience(List.of(audience));
        if (exp != null) claims.expiresAt(exp);
        return encoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(),claims.build())).getTokenValue();
    }
    @Test void expiredTokenIsDenied() throws Exception {
        mvc.perform(get("/api/data").header("Authorization", "Bearer " + signedToken(
                Instant.now().minusSeconds(10),SecurityConfig.AUDIENCE,SecurityConfig.ISSUER)))
                .andExpect(status().isUnauthorized());
    }
    @Test void wrongAudienceIsDenied() throws Exception {
        mvc.perform(get("/api/data").header("Authorization", "Bearer " + signedToken(
                Instant.now().plusSeconds(900),"another-client",SecurityConfig.ISSUER)))
                .andExpect(status().isUnauthorized());
    }
    @Test void wrongIssuerIsDenied() throws Exception {
        mvc.perform(get("/api/data").header("Authorization", "Bearer " + signedToken(
                Instant.now().plusSeconds(900),SecurityConfig.AUDIENCE,"another-issuer")))
                .andExpect(status().isUnauthorized());
    }
    @Test void missingExpirationIsDenied() throws Exception {
        mvc.perform(get("/api/data").header("Authorization", "Bearer " + signedToken(
                null,SecurityConfig.AUDIENCE,SecurityConfig.ISSUER)))
                .andExpect(status().isUnauthorized());
    }
    @Test void modifiedSignatureIsDenied() throws Exception {
        register("alice", "Alice");
        String[] parts = login().split("\\.");
        parts[2] = (parts[2].charAt(0) == 'A' ? "B" : "A") + parts[2].substring(1);
        mvc.perform(get("/api/data").header("Authorization", "Bearer " + String.join(".",parts)))
                .andExpect(status().isUnauthorized());
    }
    @Test void missingAudienceIsDenied() throws Exception {
        mvc.perform(get("/api/data").header("Authorization", "Bearer " + signedToken(
                Instant.now().plusSeconds(900),null,SecurityConfig.ISSUER)))
                .andExpect(status().isUnauthorized());
    }
    @Test void unsignedTokenIsDenied() throws Exception {
        register("alice", "Alice");
        String payload = login().split("\\.")[1];
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString(
                "{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        mvc.perform(get("/api/data").header("Authorization", "Bearer " + header + "." + payload + "."))
                .andExpect(status().isUnauthorized());
    }
    @Test void cookieCannotAuthenticate() throws Exception {
        register("alice", "Alice");
        mvc.perform(get("/api/data").cookie(new jakarta.servlet.http.Cookie("accessToken",login())))
                .andExpect(status().isUnauthorized());
    }
    @Test void textPlainLoginIsRejected() throws Exception {
        mvc.perform(post("/auth/login").contentType(MediaType.TEXT_PLAIN)
                .content(json.writeValueAsString(Map.of("login","alice","password",password))))
                .andExpect(status().isUnsupportedMediaType());
    }
}
