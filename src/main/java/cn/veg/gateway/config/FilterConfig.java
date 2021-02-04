package cn.veg.gateway.config;

import cn.veg.gateway.AuthFilter.AuthFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;

@Configuration
public class FilterConfig {
    @Autowired
    private BaseConfig baseConfig;

    @Bean
    @Order(-999)
    public GlobalFilter createGlobalFilter() {
        return new AuthFilter(baseConfig.getExcludePaths());
    }
}
