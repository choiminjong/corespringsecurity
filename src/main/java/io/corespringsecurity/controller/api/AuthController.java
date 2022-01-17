package io.corespringsecurity.controller.api;

import io.corespringsecurity.domain.dto.AccountDto;
import io.corespringsecurity.domain.dto.LoginDto;
import io.corespringsecurity.domain.dto.TokenDto;
import io.corespringsecurity.domain.entity.Account;
import io.corespringsecurity.security.jwt.JwtFilter;
import io.corespringsecurity.security.jwt.TokenProvider;
import io.corespringsecurity.security.service.AccountContext;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
public class AuthController {
    @Autowired
    private TokenProvider tokenProvider;

    @Autowired
    private UserDetailsService userDetailsService;

    @PostMapping("/api/auth/token")
    public ResponseEntity<TokenDto> authorize(@Valid @RequestBody LoginDto loginDto) {

        AccountContext accountContext =(AccountContext)userDetailsService.loadUserByUsername(loginDto.getUsername());
        System.out.println("accountContext = " + accountContext);

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null,accountContext.getAuthorities());
        System.out.println("authentication ==" + authenticationToken);

        //세션저장
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        String jwt = tokenProvider.createToken(authenticationToken);


        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);
        return new ResponseEntity<>(new TokenDto(jwt), httpHeaders, HttpStatus.OK);
    }
}