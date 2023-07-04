package com.exercise.security1.config.oauth;

import com.exercise.security1.auth.PrincipalDetails;
import com.exercise.security1.config.oauth.provider.impl.GoogleUserInfo;
import com.exercise.security1.config.oauth.provider.impl.KakaoUserInfo;
import com.exercise.security1.config.oauth.provider.impl.NaverUserInfo;
import com.exercise.security1.config.oauth.provider.OAuth2UserInfo;
import com.exercise.security1.domain.User;
import com.exercise.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Slf4j
@RequiredArgsConstructor
@Service
public class PrincipalOAuth2UserService extends DefaultOAuth2UserService {

    private BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        OAuth2UserInfo oAuth2UserInfo = null;

        oAuth2UserInfo = switch (userRequest.getClientRegistration().getRegistrationId()) {
            case "google" -> new GoogleUserInfo(oAuth2User.getAttributes());
            case "kakao" -> new KakaoUserInfo(oAuth2User.getAttributes());
            case "naver" -> new NaverUserInfo((Map<String, Object>) oAuth2User.getAttributes().get("response"));
            default -> throw new IllegalStateException("== Unexpected value: " + userRequest.getClientRegistration().getRegistrationId());
        };

        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String username = provider + "_" + providerId; // ex) `google_105897093875265670868`
        String password = passwordEncoder.encode("SASEUM");
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";

        User user = userRepository.findByUsername(username);

        if (user == null || user.getUsername() == null) {
            user = User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();

            User savedUser = userRepository.save(user);
        } else {
            log.debug("== already registered user: " + user.getUsername() + " ==");
        }

        return new PrincipalDetails(user, oAuth2User.getAttributes());
    }

}
