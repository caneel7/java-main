package com.caneel.main.security;

import com.caneel.main.config.CustomerUserDetailService;
import com.caneel.main.models.User;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Component
public class JWTAuthentication extends OncePerRequestFilter {

    @Autowired
    private CustomerUserDetailService customerUserDetailService;

    @Autowired
    private JWTHelper jwtHelper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException
    {
        String requestToken = request.getHeader("authorization");

        String username = null;
        String token = null;

        if(requestToken == null || !requestToken.startsWith("Bearer "))
        {
            throw new ServletException("Invalid Token");
        };

        //Header is in format "Bearer token"
        token = requestToken.split(" ")[1];
        try{
            String decodedToken = this.jwtHelper.verifyToken(token);

            UserDetails user = this.customerUserDetailService.loadUserById(decodedToken);

            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(user,null,null);
            usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        }catch (Exception exception){
            throw exception;
        }
        filterChain.doFilter(request,response);
    }
}
