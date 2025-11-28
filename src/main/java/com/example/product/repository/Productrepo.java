package com.example.product.repository;

import com.example.product.Model.Product;
import org.antlr.v4.runtime.atn.SemanticContext;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;



public interface Productrepo extends JpaRepository<Product,Long> {
   void   deleteById(Long id);

    @Query(value = "SELECT * FROM product WHERE " +
            "LOWER(name) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
            "LOWER(description) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
            "LOWER(location)LIKE LOWER(CONCAT('%', :keyword,'%'))",
            nativeQuery = true)
    List<Product> SearchProduct(@Param("keyword") String keyword);


}
