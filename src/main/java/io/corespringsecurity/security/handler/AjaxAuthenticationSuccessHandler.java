package io.corespringsecurity.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.corespringsecurity.domain.entity.Account;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private ObjectMapper objectMapper = new ObjectMapper();
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        /*
        AjaxAuthenticationProvider.java 프로바이더에서 토큰을 생성했기때문에 핸들러에서 사용할 수 있습니다.
        AjaxAuthenticationToken ajaxAuthenticationToken = new AjaxAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());
         */
        Account account = (Account)authentication.getPrincipal();

        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        //json 형태로 반환한다.
        objectMapper.writeValue(response.getWriter(),account);
    }
}
