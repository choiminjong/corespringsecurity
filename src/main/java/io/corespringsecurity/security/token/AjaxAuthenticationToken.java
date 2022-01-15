package io.corespringsecurity.security.token;

import io.corespringsecurity.domain.dto.AccountDto;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;
//
//public class AjaxAuthenticationToken extends UsernamePasswordAuthenticationToken {
//
//    private AjaxAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
//        super(principal, credentials, authorities);
//    }
//
//    public static AjaxAuthenticationToken getTokenFromAccountContext(AccountDto userDto) {
//        return new AjaxAuthenticationToken(userDto, userDto.getPassword(), userDto.getAuthorities());
//    }
//
//}
public class AjaxAuthenticationToken extends AbstractAuthenticationToken {

    private final Object principal;
    private Object credentials;

    //인증받기전 사용자 정보 (로그인 데이터)
    public AjaxAuthenticationToken(Object principal, Object credentials) {
        super(null);
        this.principal = principal;
        this.credentials = credentials;
        setAuthenticated(false);
    }

    //인증 이후 생성자 정보
    public AjaxAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {

        return this.credentials;
    }

    @Override
    public Object getPrincipal() {

        return this.principal;
    }
}
