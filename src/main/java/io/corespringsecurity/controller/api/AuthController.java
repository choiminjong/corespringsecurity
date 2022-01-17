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
    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    @Autowired
    private UserDetailsService userDetailsService;

    public AuthController(TokenProvider tokenProvider, AuthenticationManagerBuilder authenticationManagerBuilder) {
        this.tokenProvider = tokenProvider;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
    }

//    @PostMapping("/api/2")
//    public String authorize2() {
//        return "messages OK";
//    }

    @GetMapping("/api/check")
    public String authorize2(){
        return "messages OK";
    }

    @PostMapping("/api/check2")
    public String authorize3(){
        return "messages OK";
    }

    @PostMapping("/api/authenticate")
    public ResponseEntity<TokenDto> authorize(@Valid @RequestBody LoginDto loginDto) {
        String jwt="sdsdsd";
        System.out.println("loginDto getUsername = " + loginDto.getUsername());
        System.out.println("loginDto getPassword = " + loginDto.getPassword());

//        UsernamePasswordAuthenticationToken authenticationToken =
//                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        AccountContext accountContext =(AccountContext)userDetailsService.loadUserByUsername(loginDto.getUsername());
        System.out.println("accountContext = " + accountContext);

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null,accountContext.getAuthorities());

        System.out.println("authentication ==" + authenticationToken);


        String jwt2 = tokenProvider.createToken(authenticationToken);

        System.out.println("jwt2 ==" + jwt2);
//        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
////
////        System.out.println("authentication ==" + authentication);

        //String jwt = tokenProvider.createToken(authentication);

        //Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        //SecurityContextHolder.getContext().setAuthentication(authentication);


        //System.out.println("authentication = " + authentication);
        //loginDto.getUsername(), loginDto.getPassword()
//        UsernamePasswordAuthenticationToken authenticationToken =
//                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

//        String username = loginDto.getUsername();
//        String password = loginDto.getPassword();
//
//        AccountContext accountContext =(AccountContext)userDetailsService.loadUserByUsername(username);
//
//        //토큰생성
//        UsernamePasswordAuthenticationToken authenticationToken =
//                new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null,accountContext.getAuthorities());
//
//        //객체를 생성
//        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
//        System.out.println("authenticationManagerBuilder = " + authentication);
//
//        //토큰생성
//        String jwt = tokenProvider.createToken(authentication);

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);

        return new ResponseEntity<>(new TokenDto(jwt), httpHeaders, HttpStatus.OK);
    }
}