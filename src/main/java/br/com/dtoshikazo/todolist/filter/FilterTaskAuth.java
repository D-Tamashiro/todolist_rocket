package br.com.dtoshikazo.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.dtoshikazo.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

                var servletPath = request.getServletPath();

                if(servletPath.startsWith("/tasks/")) {

                    var authorization = request.getHeader("Authorization");
    
                    //Receba dados decodificados do front
                    var authEncoded = authorization.substring("Basic".length()).trim();
                    //Decodifica de base64 para array de bytes
                    byte[] authDecode = Base64.getDecoder().decode(authEncoded);
                    //Decodifica de array de bytes para String
                    var authString = new String(authDecode);
    
                    String[] credentials = authString.split(":");
                    String username = credentials[0];
                    String password = credentials[1];
    
                    //Valida usuário
                    var user = this.userRepository.findByUsername(username);
                    if(user == null) {
                        response.sendError(401);
                    } else {
                        //Valida senha
                        var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                        
                        if(passwordVerify.verified) {
                            //Realiza Tarefas
                            request.setAttribute("idUser", user.getId());
                            filterChain.doFilter(request, response);
                        } else {
                            response.sendError(401);
                        }
                    }
                } else {
                    filterChain.doFilter(request, response);
                }

    }

}
