package io.corespringsecurity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.corespringsecurity.domain.dto.AccountDto;
import io.corespringsecurity.security.token.AjaxAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Pattern;

public class AuthAPIProcessingFilter extends AbstractAuthenticationProcessingFilter {

    //JSON방식으로 데이터를 담아 요청을 하기에 해당 Json을 객체에 담기 위해 ObjectMapper를 사용한다
    private final ObjectMapper objectMapper = new ObjectMapper();

    private static final String HEADERAUTH = "Authorization";

    public AuthAPIProcessingFilter() {
        super(new AntPathRequestMatcher("/api/**"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        String authorization = request.getHeader(HEADERAUTH);
        //ystem.out.println("authorization  =" + authorization);

        if("".equals("authorization")){
            throw new IllegalStateException("Authentication is not supported");
        }else{
            if(Pattern.matches("Basic .*", authorization)){
                String authCount= authorization.replaceAll("Basic ", "");
                //System.out.println("replaceAll authCount = " + authCount);

                byte[] decodedBytes = Base64.getDecoder().decode(authCount);
                String decodedAuthCount = new String(decodedBytes);

                //System.out.println("decodedAuthCount  = " + decodedAuthCount);
                String[] splitCount= decodedAuthCount.split(":");

                //AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);

                AccountDto accountDto = new AccountDto();
                accountDto.setUsername(splitCount[0]);
                accountDto.setPassword(splitCount[1]);
                accountDto.setRoles(Arrays.asList("ROLE_USER"));

                //System.out.println("accountDto == " +accountDto );

                //null 데이터 체크이후 토큰을 발생해서 인증처리합니다.
                AjaxAuthenticationToken ajaxAuthenticationToken = new AjaxAuthenticationToken(accountDto.getUsername(), accountDto.getPassword());
                //AjaxAuthenticationToken ajaxAuthenticationToken = AjaxAuthenticationToken.getTokenFromAccountContext(accountDto);
                //System.out.println("ajaxAuthenticationToken" + ajaxAuthenticationToken);

                return this.getAuthenticationManager().authenticate(ajaxAuthenticationToken);
            }
        }

        //AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);
        //AjaxAuthenticationToken ajaxAuthenticationToken = AjaxAuthenticationToken.getTokenFromAccountContext(accountDto);
        return  null;
    }

    private boolean isAjax(HttpServletRequest request) {
        return "XMLHttpRequest".equals(request.getHeader("X-Requested-With"));
    }
}
