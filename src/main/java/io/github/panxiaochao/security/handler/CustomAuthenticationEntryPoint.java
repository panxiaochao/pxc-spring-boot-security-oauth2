package io.github.panxiaochao.security.handler;

import io.github.panxiaochao.common.response.ResultResponse;
import io.github.panxiaochao.jwt.utils.JacksonUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * 无效Token异常类重新，统一返回Json格式
 *
 * @author Mr_LyPxc
 */
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final Logger log = LoggerFactory.getLogger(CustomAuthenticationEntryPoint.class);

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        log.info(">>> CustomAuthenticationEntryPoint");
        //
        Throwable cause = authException.getCause();
        log.info(">>> Throwable: ", cause);
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setHeader("Content-Type", "application/json;charset=UTF-8");
        PrintWriter out = response.getWriter();
        // if (cause instanceof InvalidTokenException) {
        //    out.write(JacksonUtils
        //            .toString(ResultResponse.error(HttpStatus.FORBIDDEN.value(), "OAUTH_TOKEN_ILLEGAL")));
        //
        //} else {
        //    out.write(JacksonUtils
        //            .toString(ResultResponse.error(HttpStatus.UNAUTHORIZED.value(), "OAUTH_TOKEN_MISSING")));
        //}

        out.write(JacksonUtils
                .toString(ResultResponse.error(HttpStatus.UNAUTHORIZED.value(), "OAUTH_TOKEN_ILLEGAL")));
        out.flush();
        out.close();
    }
}
