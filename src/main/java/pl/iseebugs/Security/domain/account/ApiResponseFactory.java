package pl.iseebugs.Security.domain.account;

import org.springframework.http.HttpStatus;
import pl.iseebugs.Security.domain.ApiResponse;

public class ApiResponseFactory {
    public static <T> ApiResponse<T> createSuccessResponse(String message, T data) {
        return ApiResponse.<T>builder()
                .statusCode(HttpStatus.OK.value())
                .message(message)
                .data(data)
                .build();
    }

    public static <T> ApiResponse<T> createResponseWithoutData(int statusCode, String message) {
        return ApiResponse.<T>builder()
                .statusCode(statusCode)
                .message(message)
                .build();
    }

    public static <T> ApiResponse<T> createResponseWithStatus(int statusCode, String message, T data) {
        return ApiResponse.<T>builder()
                .statusCode(statusCode)
                .message(message)
                .data(data)
                .build();
    }
}
