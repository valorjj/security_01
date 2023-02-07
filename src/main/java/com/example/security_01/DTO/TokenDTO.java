package com.example.security_01.DTO;


import lombok.*;

@Getter
@Setter
// @NoArgsConstructor(access = AccessLevel.PROTECTED)
@NoArgsConstructor
@AllArgsConstructor
public class TokenDTO {

    private String userId;
    private String accessToken;
    private String refreshToken;
}
