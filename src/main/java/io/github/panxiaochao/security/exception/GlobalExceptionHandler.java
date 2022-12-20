package io.github.panxiaochao.security.exception;

import io.github.panxiaochao.common.response.ResultResponse;
import io.github.panxiaochao.common.utils.ExceptionUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * {@code GlobalExceptionHandler}
 * <p> RestControllerAdvice 增强
 *
 * @author Lypxc
 * @since 2022-01-22
 */
@RestControllerAdvice
public class GlobalExceptionHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /**
     * 常规兜底报错
     *
     * @param e Exception
     * @return ResultResponse
     */
    @ExceptionHandler(value = Exception.class)
    public ResultResponse<String> exception(Exception e) {
        LOGGER.error(">>> exception: {}", ExceptionUtil.getMessage(e));
        return ResultResponse.error(e.getMessage());
    }

}
