package io.github.panxiaochao.security.handler;

import io.github.panxiaochao.common.response.ResultResponse;
import io.github.panxiaochao.common.utils.JacksonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * 权限不足异常类重写
 *
 * @author LyPxc
 */
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
    private final Logger log = LoggerFactory.getLogger(CustomAccessDeniedHandler.class);

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        log.info(">>> CustomAccessDeniedHandler");
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setHeader("Content-Type", "application/json;charset=UTF-8");
        PrintWriter out = response.getWriter();
        out.write(JacksonUtil.toString(ResultResponse.error(HttpStatus.FORBIDDEN.value(), "OAUTH_TOKEN_DENIED")));
        out.flush();
        out.close();
    }
}
