package demo.bootsecurity;

import com.auth0.jwt.JWT;
import demo.bootsecurity.db.UserRepository;
import demo.bootsecurity.model.User;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.auth0.jwt.algorithms.Algorithm.HMAC512;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JWTAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        // Lee el header de la autorizacion del JWT token
        String header = request.getHeader(JWTProperties.HEADER_STRING);

        if (header == null || !header.startsWith(JWTProperties.TOKEN_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        // Convertimos a UserTODO desde la DB
        Authentication authentication = getUsernamePasswordAuthentication(request);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Continua el filter
        chain.doFilter(request, response);
    }

    private Authentication getUsernamePasswordAuthentication(HttpServletRequest request) {
        String token = request.getHeader(JWTProperties.HEADER_STRING)
                .replace(JWTProperties.TOKEN_PREFIX,"");

        if (token != null) {
            // parseamos el token y lo validamos
            String userName = JWT.require(HMAC512(JWTProperties.SECRET.getBytes()))
                    .build()
                    .verify(token)
                    .getSubject();

            // Buscamos en la DB el usuario mediante el token username
            if (userName != null) {
                User user = userRepository.findByName(userName);
                UserTODO todo = new UserTODO(user);
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(userName, null, todo.getAuthorities());
                return auth;
            }
            return null;
        }
        return null;
    }
}
