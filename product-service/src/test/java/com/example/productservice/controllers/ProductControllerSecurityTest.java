package com.example.productservice.controllers;

import com.example.productservice.models.dto.req.CreateProductReq;
import com.example.productservice.models.dto.res.ProductRes;
import com.example.productservice.models.services.ProductService;
import com.example.productservice.security.SecurityConfig;
import com.example.productservice.security.filter.CorrelationIdFilter;
import com.example.productservice.security.filter.JwtAuthenticationFilter;
import com.example.productservice.security.handler.CustomAccessDeniedHandler;
import com.example.productservice.security.handler.CustomAuthenticationEntryPoint;
import com.example.productservice.security.jwt.JwtTokenValidator;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;

import java.math.BigDecimal;
import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(ProductController.class)
@Import({
        SecurityConfig.class,
        JwtAuthenticationFilter.class,
        CorrelationIdFilter.class,
        JwtTokenValidator.class,
        CustomAuthenticationEntryPoint.class,
        CustomAccessDeniedHandler.class
})
@TestPropertySource(properties = {
        "app.jwt.secret=404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970"
})
class ProductControllerSecurityTest {

    private static final String SECRET_KEY = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private ProductService productService;

    private String userToken;
    private String adminToken;

    @BeforeEach
    void setUp() {
        userToken = generateToken("user1", List.of("ROLE_USER"));
        adminToken = generateToken("admin1", List.of("ROLE_ADMIN"));
    }

    private String generateToken(String username, List<String> roles) {
        Key key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(SECRET_KEY));
        return Jwts.builder()
                .setSubject(username)
                .addClaims(Map.of("username", username, "roles", roles))
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600000))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    @Test
    @DisplayName("Kịch bản 1 (Thử sai): DELETE /api/products/1 với Token ROLE_USER nhận 403 Forbidden")
    void deleteProductWithUserTokenShouldReturn403() throws Exception {
        mockMvc.perform(delete("/api/products/1")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.error").value("Forbidden"));

        verify(productService, never()).deleteProduct(any());
    }

    @Test
    @DisplayName("Kịch bản 2 (Thử đúng): DELETE /api/products/1 với Token ROLE_ADMIN nhận 204 No Content")
    void deleteProductWithAdminTokenShouldReturn204() throws Exception {
        doNothing().when(productService).deleteProduct(1L);

        mockMvc.perform(delete("/api/products/1")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isNoContent());

        verify(productService).deleteProduct(1L);
    }

    @Test
    @DisplayName("Chưa đăng nhập (No Token): GET /api/products trả về 401 Unauthorized")
    void getProductsWithoutTokenShouldReturn401() throws Exception {
        mockMvc.perform(get("/api/products"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.error").value("Unauthorized"));
    }

    @Test
    @DisplayName("Đã đăng nhập ROLE_USER: GET /api/products trả về 200 OK")
    void getProductsWithUserTokenShouldReturn200() throws Exception {
        ProductRes product = ProductRes.builder()
                .id(1L)
                .name("Laptop")
                .description("Gaming Laptop")
                .price(BigDecimal.valueOf(1500))
                .stock(10)
                .category("Electronics")
                .createdAt(java.time.LocalDateTime.now())
                .updatedAt(java.time.LocalDateTime.now())
                .build();
        when(productService.getAllProducts(any(Pageable.class))).thenReturn(new PageImpl<>(List.of(product)));

        mockMvc.perform(get("/api/products")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].name").value("Laptop"));

        verify(productService).getAllProducts(any(Pageable.class));
    }

    @Test
    @DisplayName("Đã đăng nhập ROLE_USER: POST /api/products trả về 403 Forbidden")
    void createProductWithUserTokenShouldReturn403() throws Exception {
        CreateProductReq req = new CreateProductReq("Laptop", "Desc", BigDecimal.valueOf(100), 5, "Cat");

        mockMvc.perform(post("/api/products")
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403));

        verify(productService, never()).createProduct(any());
    }

    @Test
    @DisplayName("Đã đăng nhập ROLE_ADMIN: POST /api/products trả về 201 Created")
    void createProductWithAdminTokenShouldReturn201() throws Exception {
        CreateProductReq req = new CreateProductReq("Laptop", "Desc", BigDecimal.valueOf(100), 5, "Cat");
        ProductRes res = ProductRes.builder()
                .id(1L)
                .name("Laptop")
                .description("Desc")
                .price(BigDecimal.valueOf(100))
                .stock(5)
                .category("Cat")
                .createdAt(java.time.LocalDateTime.now())
                .updatedAt(java.time.LocalDateTime.now())
                .build();
        when(productService.createProduct(any(CreateProductReq.class))).thenReturn(res);

        mockMvc.perform(post("/api/products")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.name").value("Laptop"));

        verify(productService).createProduct(any(CreateProductReq.class));
    }
}
