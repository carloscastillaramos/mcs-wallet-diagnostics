package pe.gob.mtc.wallet.diagnostics;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@ConfigurationPropertiesScan
@EnableScheduling
public class DiagnosticsApplication {
    public static void main(String[] args) {
        SpringApplication.run(DiagnosticsApplication.class, args);
    }
}
