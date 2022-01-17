package io.corespringsecurity.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.corespringsecurity.domain.entity.Account;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.http.HttpResponse;

public class AjaxAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private ObjectMapper objectMapper = new ObjectMapper();

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        String savedRequest = request.getRequestURI();

        System.out.println("savedRequest = " + savedRequest);
        //세션처리
        //request.getSession(false).setMaxInactiveInterval(3600);

        if(savedRequest!=null) {
            redirectStrategy.sendRedirect(request, response, "/login2");
        } else {
            redirectStrategy.sendRedirect(request, response, "/login");
        }


//        response.setCharacterEncoding("UTF-8");
//        response.setStatus(HttpStatus.OK.value());
//        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//        objectMapper.writeValue(response.getWriter(), "log-in successful");

    }

}
