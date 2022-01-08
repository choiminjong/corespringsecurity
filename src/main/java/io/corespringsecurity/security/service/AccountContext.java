package io.corespringsecurity.security.service;

import io.corespringsecurity.domain.entity.Account;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.List;

@Getter
@Setter
public class AccountContext extends User {

    private final Account account;

    public AccountContext(Account account, Collection<? extends GrantedAuthority> authorities) {
        super(account.getUsername(), account.getPassword(), authorities);
        this.account = account;
    }

    public Account getAccount(){
        return account;
    }

//    private Account account;
//
//    public AccountContext(Account account, List<GrantedAuthority> roles) {
//        super(account.getUsername(), account.getPassword(), roles);
//        this.account = account;
//    }

}
