package cn.veg.gateway.AuthFilter;

import cn.veg.common.response.ResponseBody;
import cn.veg.common.token.JWTManager;
import cn.veg.common.utils.JacksonUtil;
import cn.veg.common.utils.StringUtil;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.util.CollectionUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class AuthFilter implements GlobalFilter {
    private List<String> excludePaths;
    private JWTManager jwtManager;


    public AuthFilter(List<String> excludePaths, JWTManager jwtManager) {
        this.excludePaths = excludePaths != null ? excludePaths : new ArrayList<>();
        this.jwtManager = jwtManager;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        ServerHttpResponse response = exchange.getResponse();

        try {
            String path = request.getURI().getPath();
            if (ignore(path))
                return chain.filter(exchange);

            List<String> tokens = request.getHeaders().get("token");
            if (CollectionUtils.isEmpty(tokens) || StringUtil.isEmpty(tokens.get(0))) {
                return error(response);
            }

            ServerHttpRequest mutateRequest = exchange.getRequest()
                    .mutate()
                    .header("token", JacksonUtil.parse(jwtManager.decodeToken(tokens.get(0))))
                    .build();
            return chain.filter(exchange.mutate().request(mutateRequest).build());
        } catch (Exception e) {
            return error(response);
        }
    }

    private boolean ignore(String path) {
        boolean ignore = excludePaths
                .stream()
                .filter(p -> p.contains("/**"))
                .map(p -> p.replace("/**", ""))
                .anyMatch(path::startsWith);
        if (ignore)
            return true;
        ignore = excludePaths
                .stream()
                .filter(p -> !p.contains("/**"))
                .anyMatch(path::equals);
        return ignore;
    }

    private Mono<Void> error(ServerHttpResponse response) {
        ResponseBody body = new ResponseBody();
        body.init(HttpStatus.UNAUTHORIZED.value(), "身份验证失败");

        response.getHeaders().add("Content-Type", "application/json;charset=UTF-8");
        response.getHeaders().add("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        DataBuffer dataBuffer = response.bufferFactory().wrap(JacksonUtil.parse(body).getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(dataBuffer));
    }
}
