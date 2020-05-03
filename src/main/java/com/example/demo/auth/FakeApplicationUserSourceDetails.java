package com.example.demo.auth;

import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.example.demo.configuration.UserRole.*;

// One of the implementations of ApplicationUserRepository, multiple user sources can be created based on different databases
@Repository("fake")
@AllArgsConstructor
public class FakeApplicationUserSourceDetails implements ApplicationUserRepository{

    private final PasswordEncoder passwordEncoder;

    @Override
    public Optional<ApplicationUser> getApplicationUserDetail(String username) {
        return getApplicationUsers().stream()
                .filter(applicationUser -> applicationUser.getUsername().equals(username)).findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {
        ApplicationUser applicationUser1 = new ApplicationUser(STUDENT.getGrantedAuthorities(),
                "dhana",passwordEncoder.encode("password"), true, true,
                true, true);
        ApplicationUser applicationUser2 = new ApplicationUser(ADMIN.getGrantedAuthorities(),
                "dhana1310",passwordEncoder.encode("password"), true, true,
                true,true);
        ApplicationUser applicationUser3 = new ApplicationUser(ADMIN_TRAINEE.getGrantedAuthorities(),
                "mandeep",passwordEncoder.encode("password"), true, true,
                true,true);
        ApplicationUser applicationUser4 = new ApplicationUser(GENERAL_USER.getGrantedAuthorities(),
                "famia",passwordEncoder.encode("password"), true, true,
                true,true);

        return List.of(applicationUser1, applicationUser2, applicationUser3, applicationUser4);
    }
}
