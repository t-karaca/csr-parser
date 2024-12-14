package de.karaca.csrparser.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class SPAController {
    @GetMapping(value = "{path:^(?!api|public|assets)[^\\.]*}/**")
    public String forward() {
        return "forward:/";
    }
}
