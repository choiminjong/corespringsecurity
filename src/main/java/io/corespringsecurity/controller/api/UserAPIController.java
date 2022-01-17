package io.corespringsecurity.controller.api;

import io.corespringsecurity.domain.dto.AccountDto;
import io.corespringsecurity.domain.entity.Account;
import io.corespringsecurity.service.UserService;
import io.corespringsecurity.service.impl.UserServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class UserAPIController {

    @Autowired
    private UserService userService;

    @GetMapping("/api/v1/hello")
    public ResponseEntity<String> hello() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("authentication = " + authentication);
        return ResponseEntity.ok("hello");
    }

    @PostMapping("/api/v1/hello")
    public ResponseEntity<String> hello2() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("authentication = " + authentication);
        return ResponseEntity.ok("hello");
    }

    @GetMapping("/api/v1/user")
    @PreAuthorize("hasAnyRole('ADMIN')")
    public String getMyUserInfo() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        //Account accout = (Account) authentication.getPrincipal();
        System.out.println("authentication = " + authentication);
        return null;
    }

    @GetMapping("/api/v1/user/{username}")
    //@PreAuthorize("hasAnyRole('ADMIN')")
    public String getUserInfo(@PathVariable String username) {
        return username;
       // return ResponseEntity.ok(userService.getUserWithAuthorities(username));
    }

}
