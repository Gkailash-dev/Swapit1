package com.example.product.service;

import com.example.product.Model.Category;
import com.example.product.repository.Categoryrepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;

@Service
public class CategoryService {
    @Autowired
    private Categoryrepo categoryrepo;
    public List<Category> getAllCategory() {
        return categoryrepo.findAll();


    }

    public Category addcategory(String name) {
        Category category=new Category();
         category.setName(name);
        return  categoryrepo.save(category);

    }



}
