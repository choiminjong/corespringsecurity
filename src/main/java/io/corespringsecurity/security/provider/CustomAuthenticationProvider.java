package io.corespringsecurity.security.provider;

import io.corespringsecurity.security.common.FormWebAuthenticationDetails;
import io.corespringsecurity.security.service.AccountContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public CustomAuthenticationProvider(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

//    public CustomAuthenticationProvider(PasswordEncoder passwordEncoder) {
//        this.passwordEncoder = passwordEncoder;
//    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String username = authentication.getName();
        String password = (String) authentication.getCredentials();

        AccountContext accountContext =(AccountContext)userDetailsService.loadUserByUsername(username);

        //System.out.println("accountContext == " + accountContext);
        //accountContext == io.corespringsecurity.security.service.AccountContext
        // [Username=admin, Password=[PROTECTED], Enabled=true, AccountNonExpired=true, credentialsNonExpired=true,
        // AccountNonLocked=true, Granted Authorities=[ROLE_ADMIN, ROLE_MANAGER, ROLE_USER]]

        //System.out.println("accountContext.getAuthorities(); == " + accountContext.getAuthorities());
        //accountContext.getAuthorities(); == [ROLE_ADMIN, ROLE_MANAGER, ROLE_USER]


        if(!passwordEncoder.matches(password, accountContext.getAccount().getPassword())){
            System.out.println("BadCredentialsException");
            throw new BadCredentialsException("BadCredentialsException");
        }

        String secretKey = ((FormWebAuthenticationDetails) authentication.getDetails()).getSecretKey();
        if (secretKey == null || !secretKey.equals("secret")) {
            throw new InsufficientAuthenticationException("Invalid Secret");
        }

        //System.out.println("accountContext.getAuthorities() == " + accountContext.getAuthorities());
        //accountContext.getAuthorities() == [ROLE_ADMIN, ROLE_MANAGER, ROLE_USER]

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null,accountContext.getAuthorities());

        System.out.println("FORM authenticationToken = " + authenticationToken);
        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        //return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
