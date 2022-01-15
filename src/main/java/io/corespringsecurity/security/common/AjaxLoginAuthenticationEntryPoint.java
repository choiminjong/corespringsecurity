package io.corespringsecurity.security.common;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/*
인증을 받지 않는 상태로 자원이 접근한 익명사용자
 */
public class AjaxLoginAuthenticationEntryPoint implements AuthenticationEntryPoint {
    ObjectMapper objectMapper = new ObjectMapper();

    @Override
    //  인증오류 발생할 경우 해당 객체로이동 후 리턴한다.
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {

//        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//        response.setStatus(HttpStatus.UNAUTHORIZED.value());
//        response.getWriter().write(objectMapper.writeValueAsString(HttpServletResponse.SC_UNAUTHORIZED));

        System.out.println("AJAX UnAuthorized Error ");
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED,"UnAuthorized");

    }
}
