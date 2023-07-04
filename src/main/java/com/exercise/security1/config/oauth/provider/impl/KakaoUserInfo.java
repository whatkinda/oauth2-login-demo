package com.exercise.security1.config.oauth.provider.impl;

import com.exercise.security1.config.oauth.provider.OAuth2UserInfo;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;

@Slf4j
public class KakaoUserInfo implements OAuth2UserInfo {

    private Map<String, Object> attributes;

    public KakaoUserInfo(Map<String, Object> attributes) {
        log.info("==== 카카오 로그인 요청 ====");

        this.attributes = attributes;
    }

    @Override
    public String getProviderId() {
        return attributes.get("id").toString();
    }

    @Override
    public String getProvider() {
        return "kakao";
    }

    @Override
    public String getEmail() {
        Map<String, Object> properties = (Map<String, Object>) attributes.get("kakao_account");

        return (String) properties.get("email");
    }

    @Override
    public String getName() {
        Map<String, Object> properties = (Map<String, Object>) attributes.get("kakao_account");
        Map<String, Object> profiles = (Map<String, Object>) properties.get("profile");

        return (String) profiles.get("nickname");
    }
}
