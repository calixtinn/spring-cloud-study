package calixto.study.course;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@EntityScan({"calixto.study.core.model"})
@EnableJpaRepositories({"calixto.study.core.service.repository"})
public class SpringBootMicroservicesApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringBootMicroservicesApplication.class, args);
    }

}
