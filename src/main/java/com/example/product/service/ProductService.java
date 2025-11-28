package com.example.product.service;

import com.example.product.CloudinaryService;
import com.example.product.Model.Product;
import com.example.product.repository.Productrepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@Service


public class ProductService {
    @Autowired
    Productrepo productrepo;
    @Autowired
    private CloudinaryService cloudinaryService;

    public List<Product> getallproduct() {
        return productrepo.findAll();

    }
    public List<Product> allproduct() {
        return productrepo.findAll();

    }
    public Product addproduct(String name, String description, MultipartFile file, Double price,String quantity,String email,Long phone_number,String location) {
        try {

            String imageUrl = cloudinaryService.uploadImage(file);
            // 5. Save product in DB
            Product product = new Product();
            product.setName(name);
            product.setDescription(description);
            product.setImage(imageUrl); // store only filename in DB
            product.setPrice(price);

            product.setQuantity(quantity);
            product.setPhone_number(phone_number);
            product.setLocation(location);
            product.setEmail(email);

            return productrepo.save(product);

        } catch (IOException e) {
            throw new RuntimeException("Failed to store file: " + e.getMessage(), e);
        }
    }

    public String deleteProductById(Long id) {
        productrepo.deleteById(id);
        return "deleted";
    }

    public List<Product> SearchProduct(String keyword) {
        return  productrepo.SearchProduct(keyword);
    }

    public List<Product> product() {
        return productrepo.findAll();
    }

    public List<Product> searchProducts(String keyword) {
        return  productrepo.SearchProduct(keyword);
    }
}
