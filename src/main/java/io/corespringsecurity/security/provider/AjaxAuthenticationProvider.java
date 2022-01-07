package io.corespringsecurity.security.provider;

import io.corespringsecurity.security.common.FormWebAuthenticationDetails;
import io.corespringsecurity.security.service.AccountContext;
import io.corespringsecurity.security.token.AjaxAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

public class AjaxAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;


    public AjaxAuthenticationProvider(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        /*
         로그인시도시 authentication 객체에 데이터가 매핑되어있습니다.
         로그인 시도한 데이터를 추출해서 사용자가있는지 없는지 판별합니다.
         */
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();
        AccountContext accountContext =(AccountContext)userDetailsService.loadUserByUsername(username);

        /*
        DB에서 데이터를 추출해서 passwordEncoder.matches 함수를 사용해 복호화 후 비교를 합니다.
         */
        if(!passwordEncoder.matches(password, accountContext.getAccount().getPassword())){
            System.out.println("BadCredentialsException");
            throw new BadCredentialsException("BadCredentialsException");
        }

        //UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null,accountContext.getAuthorities());
        /*
        인증이 성공하면(조건이 발생하는 오류없다면)
        accountContext.getAccount(),  --사용자 정보 객체
        null, -- 패스워드
        accountContext.getAuthorities()) -- 권한정보
        AjaxAuthenticationToken 3개의 객체 데이터 기반으로 토큰을 생성해서 반환한다.
         */
        AjaxAuthenticationToken ajaxAuthenticationToken = new AjaxAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());
        return ajaxAuthenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {

        return authentication.equals(AjaxAuthenticationToken.class);
    }
}

