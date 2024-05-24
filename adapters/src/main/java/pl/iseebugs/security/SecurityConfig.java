package pl.iseebugs.security;

import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import pl.iseebugs.appuser.AppUserFacade;

@Configuration
@AllArgsConstructor
@EnableWebSecurity
@EnableMethodSecurity
class SecurityConfig {

    private final PasswordEncoder passwordEncoder;
    private final AppUserFacade appUserFacade;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{
        httpSecurity.csrf(AbstractHttpConfigurer::disable)                  //temporary
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/","/api/auth/**").permitAll()
                        .requestMatchers("/api/auth/user/**").hasAnyAuthority("USER", "ADMIN")
                        .anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults())
                .formLogin(Customizer.withDefaults());
        return httpSecurity.build();
    }

    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(appUserFacade);
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder.bCryptPasswordEncoder());
        return daoAuthenticationProvider;
    }

}
