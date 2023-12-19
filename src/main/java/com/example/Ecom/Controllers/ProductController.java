package com.example.Ecom.Controllers;

import com.example.Ecom.Classes.Product;
import com.example.Ecom.DTO.ApiResponse;
import com.example.Ecom.Repositories.ProductRepository;
import com.example.Ecom.Services.ProductService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api/v1/product")
@PreAuthorize("hasAnyRole('USER','ADMIN')")
public class ProductController {
    @Autowired
    private ProductRepository productRepository;
    @Autowired
    private ProductService productService;

    private ResponseEntity<?> handleValidationErrors(BindingResult bindingResult){
        Map<String,String> errors = new HashMap<>();
        for (FieldError error : bindingResult.getFieldErrors()){
            errors.put(error.getField(),error.getDefaultMessage());
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errors);
    }
    @GetMapping
    @PreAuthorize("hasAnyAuthority('user:read','admin:read')")
    public ResponseEntity<ApiResponse<List<Product>>> getAllProducts() {
        try {
            List<Product> products = productService.getAllProducts();
            return ResponseEntity.ok(new ApiResponse<>(200, "Products retrieved", products));
        } catch (Exception e) {
            return ResponseEntity.status(500).body(new ApiResponse<>(500, "An error occurred while retrieving the products", new ArrayList<>()));
        }
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<Product>> getProductById(@PathVariable Long id) {
        try {
            Optional<Product> productOptional = productService.getProductById(id);

            if (productOptional.isPresent()) {
                return ResponseEntity.ok(new ApiResponse<>(200, "Product retrieved successfully", productOptional.get()));
            } else {
                return ResponseEntity.status(404).body(new ApiResponse<>(404, "Product not found", null));
            }
        } catch (Exception e) {
            return ResponseEntity.status(500).body(new ApiResponse<>(500, "An error occurred while retrieving the product", null));
        }
    }
    @PostMapping
    @PreAuthorize("hasAuthority('admin:create')")
    public ResponseEntity<ApiResponse<List<Product>>> createProduct(@Valid @RequestBody Product product, BindingResult result) {
        try {
            if (result.hasErrors()) {
                return ResponseEntity.badRequest().body(new ApiResponse<>(400, "Please Check if you have added the product correctly", new ArrayList<>()));
            }

            return productService.saveProduct(product);
        } catch (Exception e) {
            // Log the exception for internal analysis if needed
            return ResponseEntity.status(500).body(new ApiResponse<>(500, "Internal server error.", new ArrayList<>()));
        }
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('admin:update')")
    public ResponseEntity<ApiResponse<List<Product>>> updateproduct(@PathVariable Long id,@Valid @RequestBody Product product, BindingResult result){
        try{
            if(result.hasErrors()){
                return ResponseEntity.badRequest().body(new ApiResponse<>(400, "Please Check if you have added the product correctly", new ArrayList<>()));
            }
            return productService.updateProduct(id,product);
        }catch (Exception e){
            // Log the exception for internal analysis if needed
            return ResponseEntity.status(500).body(new ApiResponse<>(500, "Internal server error.", new ArrayList<>()));
        }
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('admin:delete')")
    public ResponseEntity<ApiResponse<List<Void>>>deleteProduct(@PathVariable Long id){
        try{
            return productService.deleteProduct(id);
        }catch (Exception e){
            // Log the exception for internal analysis if needed
            return ResponseEntity.status(500).body(new ApiResponse<>(500, "Internal server error.", new ArrayList<>()));
        }
    }

}
