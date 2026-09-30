package com.example.productservice.controllers;

import com.example.productservice.models.dto.req.CreateProductReq;
import com.example.productservice.models.dto.req.UpdateProductReq;
import com.example.productservice.models.dto.res.ProductRes;
import com.example.productservice.models.services.ProductService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * ProductController — CRUD API cho Product Service.
 *
 * Phân quyền được thực hiện dựa trên header X-User-Role do API Gateway inject vào sau khi
 * verify JWT thành công. Service này KHÔNG tự parse JWT — tin tưởng Gateway đã làm điều đó.
 *
 * Quy tắc phân quyền:
 * - GET /api/products        : Tất cả user đã xác thực
 * - GET /api/products/{id}   : Tất cả user đã xác thực
 * - POST /api/products        : CHỈ ROLE_ADMIN
 * - PUT /api/products/{id}    : CHỈ ROLE_ADMIN
 * - DELETE /api/products/{id} : CHỈ ROLE_ADMIN
 */
@Slf4j
@RestController
@RequestMapping("/api/products")
@RequiredArgsConstructor
public class ProductController {

    private static final String ROLE_ADMIN = "ROLE_ADMIN";
    private static final String HEADER_USER_ROLE = "X-User-Role";
    private static final String HEADER_USER_ID = "X-User-Id";
    private static final String HEADER_CORRELATION_ID = "X-Correlation-Id";

    private final ProductService productService;

    /**
     * GET /api/products — Lấy danh sách sản phẩm có phân trang.
     * Tất cả user đã xác thực đều có thể truy cập.
     */
    @GetMapping
    public ResponseEntity<Page<ProductRes>> getAllProducts(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "id") String sortBy,
            @RequestParam(defaultValue = "asc") String sortDir,
            @RequestHeader(value = HEADER_USER_ID, required = false) String userId,
            @RequestHeader(value = HEADER_CORRELATION_ID, required = false) String correlationId
    ) {
        log.debug("[{}] GET /api/products — user: '{}'", correlationId, userId);
        Sort sort = sortDir.equalsIgnoreCase("desc") ? Sort.by(sortBy).descending() : Sort.by(sortBy).ascending();
        Pageable pageable = PageRequest.of(page, size, sort);
        return ResponseEntity.ok(productService.getAllProducts(pageable));
    }

    /**
     * GET /api/products/{id} — Lấy chi tiết một sản phẩm.
     * Tất cả user đã xác thực đều có thể truy cập.
     */
    @GetMapping("/{id}")
    public ResponseEntity<ProductRes> getProductById(
            @PathVariable Long id,
            @RequestHeader(value = HEADER_USER_ID, required = false) String userId,
            @RequestHeader(value = HEADER_CORRELATION_ID, required = false) String correlationId
    ) {
        log.debug("[{}] GET /api/products/{} — user: '{}'", correlationId, id, userId);
        return ResponseEntity.ok(productService.getProductById(id));
    }

    /**
     * POST /api/products — Tạo sản phẩm mới.
     * CHỈ ROLE_ADMIN. Kiểm tra header X-User-Role do Gateway inject.
     *
     * Tính toàn vẹn: header X-User-Role CHỈ được tạo bởi Gateway sau khi verify JWT thành công.
     * Client không thể tự tạo header này (Gateway sẽ ghi đè hoặc từ chối request không có JWT).
     */
    @PostMapping
    public ResponseEntity<?> createProduct(
            @Valid @RequestBody CreateProductReq req,
            @RequestHeader(value = HEADER_USER_ROLE, required = false) String userRole,
            @RequestHeader(value = HEADER_USER_ID, required = false) String userId,
            @RequestHeader(value = HEADER_CORRELATION_ID, required = false) String correlationId
    ) {
        log.info("[{}] POST /api/products — user: '{}', role: '{}'", correlationId, userId, userRole);

        // Kiểm tra quyền: chỉ ADMIN mới được tạo sản phẩm
        if (!ROLE_ADMIN.equals(userRole)) {
            log.warn("[{}] Access denied for user '{}' with role '{}' — ROLE_ADMIN required",
                    correlationId, userId, userRole);
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body("Access denied: ROLE_ADMIN is required to create products");
        }

        ProductRes created = productService.createProduct(req);
        log.info("[{}] Product created: id={}, name='{}'", correlationId, created.getId(), created.getName());
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    /**
     * PUT /api/products/{id} — Cập nhật sản phẩm.
     * CHỈ ROLE_ADMIN.
     */
    @PutMapping("/{id}")
    public ResponseEntity<?> updateProduct(
            @PathVariable Long id,
            @Valid @RequestBody UpdateProductReq req,
            @RequestHeader(value = HEADER_USER_ROLE, required = false) String userRole,
            @RequestHeader(value = HEADER_USER_ID, required = false) String userId,
            @RequestHeader(value = HEADER_CORRELATION_ID, required = false) String correlationId
    ) {
        log.info("[{}] PUT /api/products/{} — user: '{}', role: '{}'", correlationId, id, userId, userRole);

        if (!ROLE_ADMIN.equals(userRole)) {
            log.warn("[{}] Access denied for user '{}' with role '{}' on update product id={}",
                    correlationId, userId, userRole, id);
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body("Access denied: ROLE_ADMIN is required to update products");
        }

        return ResponseEntity.ok(productService.updateProduct(id, req));
    }

    /**
     * DELETE /api/products/{id} — Xoá sản phẩm.
     * CHỈ ROLE_ADMIN.
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteProduct(
            @PathVariable Long id,
            @RequestHeader(value = HEADER_USER_ROLE, required = false) String userRole,
            @RequestHeader(value = HEADER_USER_ID, required = false) String userId,
            @RequestHeader(value = HEADER_CORRELATION_ID, required = false) String correlationId
    ) {
        log.info("[{}] DELETE /api/products/{} — user: '{}', role: '{}'", correlationId, id, userId, userRole);

        if (!ROLE_ADMIN.equals(userRole)) {
            log.warn("[{}] Access denied for user '{}' with role '{}' on delete product id={}",
                    correlationId, userId, userRole, id);
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body("Access denied: ROLE_ADMIN is required to delete products");
        }

        productService.deleteProduct(id);
        return ResponseEntity.noContent().build();
    }
}
