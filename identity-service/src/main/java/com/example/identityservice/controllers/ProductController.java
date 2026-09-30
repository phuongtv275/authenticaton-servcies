package com.example.identityservice.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * ProductController — giả lập một Product Service đơn giản.
 * Mục đích: kiểm tra khả năng định tuyến đa dịch vụ của API Gateway.
 *
 * Luồng request qua Gateway:
 *   Client → GET http://localhost:8888/product/api/products
 *   Gateway → StripPrefix=1 → GET http://localhost:8080/api/products
 *   ProductController xử lý và trả về danh sách sản phẩm giả.
 */
@RestController
@RequestMapping("/api/products")
public class ProductController {

    @GetMapping
    public ResponseEntity<?> getAllProducts() {
        List<Map<String, Object>> products = List.of(
                Map.of("id", 1, "name", "Laptop Dell XPS 15", "price", 35000000, "category", "Electronics"),
                Map.of("id", 2, "name", "Chuột Logitech MX Master 3", "price", 2500000, "category", "Accessories"),
                Map.of("id", 3, "name", "Bàn phím Keychron K2", "price", 1800000, "category", "Accessories"),
                Map.of("id", 4, "name", "Màn hình LG 27UK850", "price", 12000000, "category", "Electronics")
        );

        return ResponseEntity.ok(Map.of(
                "message", "Product list fetched successfully via API Gateway",
                "total", products.size(),
                "data", products
        ));
    }
}
