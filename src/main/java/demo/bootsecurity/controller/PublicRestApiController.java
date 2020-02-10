package demo.bootsecurity.controller;

import demo.bootsecurity.model.User;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import demo.bootsecurity.db.UserRepository;

import java.util.List;

@RestController
@RequestMapping("api/public")
@CrossOrigin
public class PublicRestApiController {

    private UserRepository userRepository;

    public PublicRestApiController(UserRepository userRepository){
        this.userRepository = userRepository;
    }

    @GetMapping("test1")
    public String test1(){
        return "API Test 1";
    }

    @GetMapping("test2")
    public String test2(){
        return "API Test 2";
    }

    @GetMapping("users")
    public List<User> getUsers() {
        return this.userRepository.findAll();
    }

    @GetMapping("test")
    public String api1() {
        return "API test";
    }

    @GetMapping("management/reports")
    public String reports() {
        return "TODO report data";
    }

    @GetMapping("admin/users")
    public List<User> users() {
        return this.userRepository.findAll();
    }

}
