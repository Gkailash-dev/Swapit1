package com.example.product.controller;

import com.example.product.Model.Product;
import com.example.product.Model.User;
import com.example.product.repository.Userrepo;
import com.example.product.service.ProductService;
import com.example.product.service.Userservice;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.management.relation.Role;
import java.util.List;
import java.util.Objects;

@Controller


public class Usercontroller {
    @Autowired
    private Userservice userservice;
    private Userrepo userrepo;
    @Autowired
    private ProductService productService;


    //create a user and then show tem success page
    @PostMapping("/register")
    public String  register(@RequestParam("Username") String Username,
                            @RequestParam("Password") String Password,
                            @RequestParam("Role") String Role,
                            @RequestParam("Email") String Email, Model model)

    {
       userservice.register(Username, Password,Role,Email);
       model.addAttribute("message","user created");
       return  "tempsuccesspage";

    }

// go to create user html page
    @GetMapping("/create_user")
    public  String createuser(){
        return "create_user_html";
    }

    // if user is loged in then go to next dasboard
    @GetMapping("/user/dashboard")
    public  String Userdashbord(){
        return  "user_dashboard";
    }


    @GetMapping("/user/user_product")
    public String product(Model model) {

        List<Product> products = productService.product();
        model.addAttribute("products", products);
        return "temp";
    }

//that show on first UI
    @GetMapping("/")
    public  String homepage(){
        return "redirect:/Access_by_customer_product";
    }


    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user/login")
    public  String  Userlogin(){
        return "userlogin";
    }


    @GetMapping("/login")
    public  String  login(){
        return "userlogin";
    }
//admin access user list
    @GetMapping("/admin/listuser")
    public String  listuser(Model model){

        List<User> u= userservice.listuser();
        model.addAttribute("user",u);
        return "listuser";
    }




}




