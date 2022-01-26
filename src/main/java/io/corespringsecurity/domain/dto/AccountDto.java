package io.corespringsecurity.domain.dto;

import lombok.Data;

import java.util.List;

@Data
public class AccountDto {

    private String id;
    private String username;
    private String email;
    private int age;
    private String password;
    private List<String> roles;
}
