package io.corespringsecurity.aopsecurity;

import io.corespringsecurity.domain.dto.AccountDto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

@Controller
public class AopSecurityController {

    @Autowired
    private AopMethodService aopMethodService;

    @Autowired
    private AopPointcutService aopPointcutService;

    @GetMapping("/preAuthorize")
    @PreAuthorize("hasRole('ROLE_USER') AND #account.username == principal.username")
    public String preAuthorize(AccountDto account, Model model, Principal principal){
        System.out.println("account.username = " + account.getUsername() + "");
        model.addAttribute("method", "Success @PreAuthorize");
        return "aop/method";
    }

    @GetMapping("/methodSecured")
    public String methodSecured(Model model){
        aopMethodService.methodSecured();
        model.addAttribute("method", "Success MethodSecured");
        return "aop/method";
    }

    @GetMapping("/pointcutSecured")
    public String pointcutSecured(Model model){
        aopPointcutService.pointcutSecured();
        aopPointcutService.notSecured();
        model.addAttribute("pointcut", "Success pointcutSecured");
        return "aop/method";
    }
}
