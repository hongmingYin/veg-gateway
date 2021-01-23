package cn.veg;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletComponentScan;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

/**
 * Hello world!
 *
 */
@EnableDiscoveryClient
@SpringBootApplication(scanBasePackages = {"cn.veg"})
public class VegGatewayApplication
{
    public static void main( String[] args )
    {
        SpringApplication.run(VegGatewayApplication.class, args);
    }
}
