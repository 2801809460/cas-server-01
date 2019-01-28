package com.it.cas.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

/**
 * @author lee
 * @date 2019/1/28
 */
@RestController
public class TestController {

    @RequestMapping("/test")
    public String test(){
        return "test hello";
    }

    @RequestMapping("/capcha")
    public String test(HttpServletRequest request){
        request.getSession().setAttribute("capcha",request.getParameter("capcha"));
        return "put capcha success";

    }


}
