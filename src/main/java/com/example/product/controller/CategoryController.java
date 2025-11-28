package com.example.product.controller;

import com.example.product.Model.Category;
import com.example.product.service.CategoryService;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@Controller

public class CategoryController {
    @Autowired
    private CategoryService categoryService;

    @GetMapping("/api/category")
    public String  getAllCategory(Model model) {
       List<Category> categories=categoryService.getAllCategory();
       model.addAttribute("category",categories);
       return "category";

    }

    @PostMapping("/create")
    public Category addcategory(@RequestParam("name") String name) {
        return categoryService.addcategory(name);

    }
   @GetMapping("/csrf")
    public CsrfToken getcsrf(HttpServletRequest request){
      return (CsrfToken) request.getAttribute("_csrf");

   }
}
