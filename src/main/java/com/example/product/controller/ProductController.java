package com.example.product.controller;

import com.example.product.Model.Product;
import com.example.product.service.ProductService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

@Controller
public class ProductController {
    @Autowired
    private ProductService productService;

    // product adding html form
    @GetMapping("/addproducthtml")
    public String productaddheml() {
        return "addproduct";
    }
    @PostMapping("/addproduct")
    //product adding end point

    public  Product addProduct(
            @RequestParam("name") String name,
            @RequestParam("description") String description,
            @RequestParam("file") MultipartFile file,
            @RequestParam("price") Double price,
            @RequestParam("quantity") String quantity,
            @RequestParam("email") String email,
            @RequestParam("phone_number") Long phoneNumber,
            @RequestParam("location") String location) {

        return productService.addproduct(name, description, file, price, quantity, email, phoneNumber, location);

    }


    //get the product  by using end point show on product.html
    @GetMapping("/Access_by_user_product")
    public String getallproduct(Model model) {

        List<Product> products = productService.getallproduct();
        model.addAttribute("products", products);
        return "product";
    }

    @GetMapping("/Access_by_customer_product")
    public String allproduct(Model model) {

        List<Product> products = productService.allproduct();
        model.addAttribute("products", products);
        return "cproduct";
    }
    @GetMapping("/product/search")

    public String  searchProducts(@RequestParam("keyword") String keyword,Model model) {
        List<Product> p = productService.searchProducts(keyword);
        model.addAttribute("p",p);
        return "product";

    }

}
