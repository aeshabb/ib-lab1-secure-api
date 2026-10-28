package ru.itmo.russu.api;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.http.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.HtmlUtils;

@RestController
public class ApiController {
    private final UserRepository users;
    private final PasswordEncoder passwords;
    private final JwtEncoder tokens;
    private final String dummyHash;

    public ApiController(UserRepository users, PasswordEncoder passwords, JwtEncoder tokens) {
        this.users = users;
        this.passwords = passwords;
        this.tokens = tokens;
        byte[] random = new byte[32];
        new SecureRandom().nextBytes(random);
        this.dummyHash = passwords.encode(Base64.getEncoder().encodeToString(random));
    }

    public record Registration(
            @NotBlank @Pattern(regexp = "[A-Za-z0-9_.-]{3,32}") String login,
            @NotBlank @Size(min = 12, max = 72) String password,
            @NotBlank @Size(max = 100) String displayName) {}
    public record Credentials(@NotBlank @Size(max = 128) String login,
                              @NotBlank @Size(max = 72) String password) {}
    public record UserView(Long id, String login, String displayName) {
        static UserView of(UserAccount u) {
            return new UserView(u.getId(), HtmlUtils.htmlEscape(u.getLogin()),
                    HtmlUtils.htmlEscape(u.getDisplayName()));
        }
    }
    public record TokenResponse(String accessToken, String tokenType, long expiresIn) {}

    @PostMapping("/auth/register")
    public ResponseEntity<UserView> register(@Valid @RequestBody Registration request) {
        checkPasswordLength(request.password());
        var user = users.saveAndFlush(new UserAccount(request.login(),
                passwords.encode(request.password()), request.displayName()));
        return ResponseEntity.status(HttpStatus.CREATED).body(UserView.of(user));
    }

    @PostMapping("/auth/login")
    public TokenResponse login(@Valid @RequestBody Credentials request) {
        checkPasswordLength(request.password());
        var user = users.findByLogin(request.login());
        String hash = user.map(UserAccount::getPasswordHash).orElse(dummyHash);
        boolean matches = passwords.matches(request.password(), hash);
        if (user.isEmpty() || !matches) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }
        Instant now = Instant.now();
        var claims = JwtClaimsSet.builder().issuer(SecurityConfig.ISSUER)
                .audience(List.of(SecurityConfig.AUDIENCE)).subject(user.get().getId().toString())
                .issuedAt(now).expiresAt(now.plusSeconds(900)).build();
        String token = tokens.encode(JwtEncoderParameters.from(
                JwsHeader.with(MacAlgorithm.HS256).build(), claims)).getTokenValue();
        return new TokenResponse(token, "Bearer", 900);
    }

    @GetMapping("/api/data")
    public List<UserView> data(@AuthenticationPrincipal Jwt jwt) {
        Long id;
        try { id = Long.valueOf(jwt.getSubject()); }
        catch (NumberFormatException e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
        var user = users.findById(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED));
        return List.of(UserView.of(user));
    }

    private static void checkPasswordLength(String password) {
        if (password.getBytes(StandardCharsets.UTF_8).length > 72) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password exceeds 72 UTF-8 bytes");
        }
    }
}
