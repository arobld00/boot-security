package demo.bootsecurity.db;

import demo.bootsecurity.model.User;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

@Service
public class DbInit implements CommandLineRunner {

    private UserRepository userRepository;

    private PasswordEncoder passwordEncoder;

    public DbInit(UserRepository userRepository, PasswordEncoder passwordEncode) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncode;

    }

    @Override
    public void run(String... args) throws Exception {
        this.userRepository.deleteAll();
        User alberto = new User("alberto", this.passwordEncoder.encode("alberto123"), "USER", "");
        User admin = new User("admin", this.passwordEncoder.encode("admin123"), "ADMIN", "ACCESS_TEST1,ACCESS_TEST2");
        User manager = new User("manager", this.passwordEncoder.encode("manager123"), "MANAGER", "ACCESS_TEST1");

        List<User> users = Arrays.asList(alberto, admin, manager);

        this.userRepository.saveAll(users);
    }
}
