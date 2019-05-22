package com.example.casclient.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class UserController {


    @GetMapping("/index")
    public String index(){
        System.err.println("/index");
        return "redirect:/user/find";
    }
    @GetMapping("/")
    public String redirect(){
        System.err.println("/");
        return "redirect:/user/find";
    }
    @ResponseBody
    @GetMapping("/user/find")
    public String findUser(){
        System.err.println("/user/find");
        return "find";
    }

    @ResponseBody
    @GetMapping("/user/delete")
    public String deleteUser(){
        return "delete";
    }

    // Login form
//    @RequestMapping("/login")
//    public String login() {
//        System.err.println("/login");
//        return "login";
//    }

    // Login form with error
    @RequestMapping("/login-error")
    public String loginError(Model model) {
        System.err.println("/login-error");
        model.addAttribute("loginError", true);
        return "login";
    }



}
