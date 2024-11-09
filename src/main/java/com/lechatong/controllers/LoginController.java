package com.lechatong.controllers;

import com.lechatong.models.LcuUser;
import com.lechatong.services.JWTService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

@RestController
public class LoginController {

    private OAuth2AuthorizedClientService authorizedClientService;

    private JWTService jwtService;

    public LoginController(OAuth2AuthorizedClientService authorizedClientService, JWTService jwtService){
        this.authorizedClientService = authorizedClientService;
        this.jwtService = jwtService;
    }

    @PostMapping("/token")
    public String getToken(Authentication authentication){
        return jwtService.generateToken(authentication);
    }

    @GetMapping("/user")
    public String getUser(){
        return "Welcome User";
    }

    @GetMapping("/admin")
    public String getAdmin(){
        return "Welcome Admin";
    }

    @GetMapping("/home")
    public String getUserInfo(Principal user, @AuthenticationPrincipal OidcUser oidcUser){
        StringBuffer userInfo = new StringBuffer();
        if(user instanceof UsernamePasswordAuthenticationToken){
            userInfo.append(getUsenamePasswordLoginInfo(user));
        }else if(user instanceof OAuth2AuthenticationToken){
            userInfo.append(getOAuth2LoginInfo(user, oidcUser));
        }
        return  userInfo.toString();
    }

    private StringBuffer getUsenamePasswordLoginInfo(Principal user){
        StringBuffer userNameInfo = new StringBuffer();
        UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken)user;
        if(token.isAuthenticated()){
            LcuUser u = (LcuUser) token.getPrincipal();
            userNameInfo.append("Welcome, " + u.getUsername());
        }else{
            userNameInfo.append("NA");
        }
        return  userNameInfo;
    }

    private StringBuffer getOAuth2LoginInfo(Principal user, OidcUser oidcUser){
        StringBuffer protectedInfo = new StringBuffer();
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken)user;
        OAuth2AuthorizedClient auth2AuthorizedClient = authorizedClientService.loadAuthorizedClient(
                token.getAuthorizedClientRegistrationId(), token.getName()
        );
        if(token.isAuthenticated()){
            Map<String, Object> userAttributes = ((DefaultOAuth2User) token.getPrincipal()).getAttributes();
            String userToken = auth2AuthorizedClient.getAccessToken().getTokenValue();
            protectedInfo.append("Welcome, " + userAttributes.get("name") + "<br><br>");
            protectedInfo.append("Email : " + userAttributes.get("email") + "<br><br>");
            protectedInfo.append("Access toke : " + userToken);

            OidcIdToken idToken = oidcUser.getIdToken();
            if(idToken != null){
                protectedInfo.append("idToken value : " + idToken.getTokenValue() + "<br>");
                protectedInfo.append("Token mapped values <br>");
                Map<String, Object> claims = idToken.getClaims();
                for(String key : claims.keySet()){
                    protectedInfo.append(" " + key + " : " + claims.get(key) + "<br>");
                }
            }
        }else{
            protectedInfo.append("NA");
        }
        return protectedInfo;
    }
}
