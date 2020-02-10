package demo.bootsecurity;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import demo.bootsecurity.db.UserRepository;
import demo.bootsecurity.model.User;

@Service
public class UserTODODetailsService implements UserDetailsService {

    private UserRepository userRepository;

    public UserTODODetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /*
    Se devuelve un usuario del repositorio. Despues, creamos un usuario mediante el patrón Decorator
    el cual implementa la interfaz usuario.
     */
    @Override
    public UserDetails loadUserByUsername(String name) throws UsernameNotFoundException {
        User user = this.userRepository.findByName(name);
        UserTODO userTODO = new UserTODO(user);
        return userTODO;
    }
}
