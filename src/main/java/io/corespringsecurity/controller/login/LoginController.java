package io.corespringsecurity.controller.login;

import io.corespringsecurity.domain.entity.Account;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.HashMap;

@Controller
public class LoginController {

    @ResponseBody
    @RequestMapping(value="/api/v1/test", method= RequestMethod.GET)
    public HashMap<String, Object> test2() {
        HashMap<String, Object> map = new HashMap<>();
        map.put("abc", "ddd");
        System.out.println("map  " + map);
        return map;
    }
    @ResponseBody
    @RequestMapping(value="/login2")
    public HashMap<String, Object> test3() {
        HashMap<String, Object> map = new HashMap<>();
        map.put("abc", "ddd");
        System.out.println("map  " + map);
        return map;
    }


    @RequestMapping(value="/login")
    public String login(@RequestParam(value = "error", required = false) String error,
                        @RequestParam(value = "exception", required = false) String exception, Model model){
        model.addAttribute("error",error);
        model.addAttribute("exception",exception);

        System.out.println("login !!!!!!");
        return "login";
    }

    @RequestMapping(value="/api/login")
    public String ajaxLogin(@RequestParam(value = "error", required = false) String error,
                            @RequestParam(value = "exception", required = false) String exception, Model model){

        model.addAttribute("error",error);
        model.addAttribute("exception",exception);
        return "login";
}


    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response){

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if(authentication != null){
            new SecurityContextLogoutHandler().logout(request,response,authentication);
        }

        return "redirect:/login";
    }

    @GetMapping(value={"/denied","/api/denied"})
    public String accessDenied(@RequestParam(value="exception",required = false) String exception, Principal principal, Model model) throws Exception {
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        Account accout = (Account) authentication.getPrincipal();

        Account account = null;

        if (principal instanceof UsernamePasswordAuthenticationToken) {
            account = (Account) ((UsernamePasswordAuthenticationToken) principal).getPrincipal();
        }

        model.addAttribute("username", account.getUsername());
        model.addAttribute("exception", exception);

        return "user/login/denied";
    }
}
