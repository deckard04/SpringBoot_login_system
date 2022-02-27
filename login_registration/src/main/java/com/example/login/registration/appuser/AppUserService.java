package com.example.login.registration.appuser;

import com.example.login.registration.Registration.token.ConfirmationToken;
import com.example.login.registration.Registration.token.ConfirmationTokenService;
import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;


@Service
@AllArgsConstructor
public class AppUserService implements UserDetailsService {

    private final static String USER_NOT_FOUND_MSG = "User with email %s not found";
    private final AppRepo appRepo;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final ConfirmationTokenService confirmationTokenService;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return appRepo.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException(String.format(USER_NOT_FOUND_MSG, email)));
    }

    public String signUpUser(AppUser appUser){
       boolean userExist = appRepo.findByEmail(appUser.getEmail()).isPresent();
       if (userExist){
           throw new IllegalStateException("Email is already taken");
       }

       String encodedPassword = bCryptPasswordEncoder.encode(appUser.getPassword());

       appUser.setPassword(encodedPassword);

       appRepo.save(appUser);

        String token = UUID.randomUUID().toString();

        ConfirmationToken confirmationToken = new ConfirmationToken(token, LocalDateTime.now(), LocalDateTime.now().plusMinutes(15), appUser);

        confirmationTokenService.saveConfirmationToken(confirmationToken);

        // TODO: SEND EMAIL

        return token;
    }

    public int enableAppUser(String email) {
        return appRepo.enableAppUser(email);
    }
}
