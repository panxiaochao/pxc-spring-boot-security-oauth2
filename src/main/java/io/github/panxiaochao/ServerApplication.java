package io.github.panxiaochao;

import org.mybatis.spring.annotation.MapperScan;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.jdbc.JdbcTemplateAutoConfiguration;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.util.StringUtils;

import java.net.InetAddress;

/**
 * @author Lypxc
 */
@SpringBootApplication(exclude = {DataSourceAutoConfiguration.class, JdbcTemplateAutoConfiguration.class})
@MapperScan("io.github.panxiaochao.web.sys.**.mapper")
public class ServerApplication {
    private static final Logger LOG = LoggerFactory.getLogger(ServerApplication.class);

    private static final String WEB_PATH = "/";

    /**
     * @param args args
     * @throws Exception Exception
     */
    public static void main(String[] args) throws Exception {
        ConfigurableApplicationContext application = SpringApplication.run(ServerApplication.class, args);
        Environment env = application.getEnvironment();
        String ip = InetAddress.getLocalHost().getHostAddress();
        String applicationName = env.getProperty("spring.application.name");
        String port = env.getProperty("server.port");
        String path = env.getProperty("server.servlet.context-path");
        if (!StringUtils.hasText(path) || WEB_PATH.equals(path)) {
            path = "";
        }
        LOG.info("\n----------------------------------------------------------\n\t{}{}{}{}",
                applicationName + " is running! Access URLs:",
                "\n\tLocal    访问网址: \thttp://localhost:" + port + path,
                "\n\tExternal 访问网址: \thttp://" + ip + ":" + port + path,
                "\n----------------------------------------------------------\n");

    }
}
