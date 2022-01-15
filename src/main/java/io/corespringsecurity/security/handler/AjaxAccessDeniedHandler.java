package io.corespringsecurity.security.handler;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;

public class AjaxAccessDeniedHandler implements AccessDeniedHandler {

    private String errorPage;

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    //접근이 불가능할때 처리하는 클래스 accessDeniedException
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {

        //response.sendError(HttpServletResponse.SC_FORBIDDEN,"Access is denied");

        String deniedUrl = errorPage + "?exception=" + URLEncoder.encode(accessDeniedException.getMessage(),"UTF-8");
        redirectStrategy.sendRedirect(request, response, deniedUrl);
    }

    public void setErrorPage(String errorPage) {
        this.errorPage = errorPage;
    }
}
