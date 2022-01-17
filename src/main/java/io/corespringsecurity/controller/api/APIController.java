package io.corespringsecurity.controller.api;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class APIController {

    @GetMapping(value = "/api/v1/hello")
    @ResponseBody
    public String apiHelloMessages() {
        return "messages OK";
    }

}
