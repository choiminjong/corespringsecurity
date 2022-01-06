package io.corespringsecurity.security.filter;

import antlr.StringUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.corespringsecurity.domain.AccountDto;
import io.corespringsecurity.security.token.AjaxAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private static final String XML_HTTP_REQUEST = "XMLHttpRequest";
    private static final String X_REQUESTED_WITH = "X-Requested-With";

    //json 데이터를 받을때 사용
    private ObjectMapper objectMapper = new ObjectMapper();

    //url /api/login 접근시 매칭확인
    public AjaxLoginProcessingFilter() {
        super(new AntPathRequestMatcher("/api/login", "POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException {


        //헤더를 확인한다. 응용 ) auth 인증 필터를 만들 수 있다.
        if(!isAjax(request)){
            throw new IllegalStateException("Authentication is nor supported");
        }

        //json 데이터를 받아서 AccountDto 매핑한다.
        AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);

        //null 데이터 체크
        if(accountDto.getUsername().isBlank() || accountDto.getPassword().isBlank() ){
            throw new IllegalArgumentException("Username or Passoword is empty");
        }

        //null 데이터 체크이후 토큰을 발생해서 인증처리합니다.
        AjaxAuthenticationToken token = new AjaxAuthenticationToken(accountDto.getUsername(),accountDto.getPassword());
        return this.getAuthenticationManager().authenticate(token);
    }

    public static boolean isAjax(HttpServletRequest request) {
        return XML_HTTP_REQUEST.equals(request.getHeader(X_REQUESTED_WITH));
    }
}
