package de.karaca.csrparser.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class SPAController {
    @GetMapping(value = "{path:^(?!api|public|assets)[^\\.]*}/**")
    public String forward() {
        // all requests should be forwarded to index.html, so routing can be done by the React frontend
        // except paths starting with /api, /public and /assets
        return "forward:/";
    }
}
