package io.corespringsecurity.domain.entity;

import lombok.*;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Entity
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED )
public class Account {

    @Id
    @GeneratedValue
    private Long Id;
    private  String username;
    private  String password;
    private  String email;
    private  String age;
    private  String role;
}
