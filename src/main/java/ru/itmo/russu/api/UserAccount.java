package ru.itmo.russu.api;

import jakarta.persistence.*;

@Entity
@Table(name = "app_users")
public class UserAccount {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false, unique = true, length = 32)
    private String login;
    @Column(nullable = false, length = 100)
    private String passwordHash;
    @Column(nullable = false, length = 100)
    private String displayName;

    protected UserAccount() {}

    public UserAccount(String login, String passwordHash, String displayName) {
        this.login = login;
        this.passwordHash = passwordHash;
        this.displayName = displayName;
    }
    public Long getId() { return id; }
    public String getLogin() { return login; }
    public String getPasswordHash() { return passwordHash; }
    public String getDisplayName() { return displayName; }
}
