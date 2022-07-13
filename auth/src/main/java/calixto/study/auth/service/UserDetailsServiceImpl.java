package calixto.study.auth.service;

import calixto.study.core.model.ApplicationUser;
import calixto.study.core.service.repository.ApplicationUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserDetailsServiceImpl implements UserDetailsService {

    private final ApplicationUserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("Searching in DB the user by username {}", username);
        ApplicationUser user = repository.findByUsername(username).orElseThrow(() ->
            new UsernameNotFoundException(String.format("Application User '%s' not found", username)));
        log.info("Application user found: {}", user);
        return User.withUsername(username)
                .roles("ROLE_" + user.getRole())
                .password(user.getPassword()).build();
    }
}
