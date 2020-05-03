package com.example.demo.auth;

import java.util.Optional;

// made an interface so that the user-source can be changed dynamically and implemented, (eg - SQL, MONGO, REDIS, PostGres)
public interface ApplicationUserRepository {

    Optional<ApplicationUser> getApplicationUserDetail(String username);
}
