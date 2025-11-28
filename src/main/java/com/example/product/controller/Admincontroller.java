package com.example.product.controller;

import com.example.product.Model.Product;
import com.example.product.service.ProductService;
import com.example.product.service.Userservice;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
public class Admincontroller {
    @Autowired
    private ProductService productService;
    @Autowired
    private Userservice userservice;


    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/login")
    public  String  Adminlogin(){
        return "adminlogin";
    }

//show Admin dasboard
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/dashboard")
    public  String Admindasbord(){
        return  "Admin_dashboard";
    }


//list the all product to view Admin
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/product")
    public String getallproduct(Model model) {
        List<Product> products = productService.getallproduct();
        model.addAttribute("products", products);
        return "productaccessbyAdmin";
    }

//delete the user by Admin
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/delete/{id}")
    public String deleteuser(@PathVariable int id){
         userservice.deleteUserById(id);
         return "redirect:/admin/listuser";
    }
    //used for delete product by admin
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/delete/product/{id}")
    public String deleteproduct(@PathVariable Long id){
        productService.deleteProductById(id);
        return "redirect:/product";
    }
}

