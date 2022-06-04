package com.example.jwt.security.v7.controller;

import com.example.jwt.security.v7.configuration.IsAdmin;
import com.example.jwt.security.v7.dto.UserDataDTO;
import com.example.jwt.security.v7.dto.UserResponseDTO;
import com.example.jwt.security.v7.model.User;
import com.example.jwt.security.v7.repository.UserRepository;
import com.example.jwt.security.v7.service.UserService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.security.Principal;

@RestController
@RequestMapping("/users")
@Api(tags = "users")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ModelMapper modelMapper;

    @PostMapping("/signin")
    @ApiOperation(value = "${UserController.signin}")
    @ApiResponses(value = {
        @ApiResponse(code = 400, message = "Something went wrong"),
        @ApiResponse(code = 422, message = "Invalid username/password supplied")})
    public String login(
        @ApiParam("Username") @RequestParam String username,
        @ApiParam("Password") @RequestParam String password) {
        return userService.signin(username, password);
    }

    @PostMapping("/signup")
    @ApiOperation(value = "${UserController.signup}")
    @ApiResponses(value = {
        @ApiResponse(code = 400, message = "Something went wrong"),
        @ApiResponse(code = 403, message = "Access denied"),
        @ApiResponse(code = 422, message = "Username is already in use"),
        @ApiResponse(code = 500, message = "Expired or invalid JWT token")})
    public String signup(@ApiParam("Signup User") @RequestBody UserDataDTO user) {
        return userService.signup(modelMapper.map(user, User.class));
    }

    @DeleteMapping(value = "/{username}")
    @PreAuthorize("hasAuthority('ADMIN_PRIVILEGE')")
    @ApiOperation(value = "${UserController.delete}")
    @ApiResponses(value = {
        @ApiResponse(code = 400, message = "Something went wrong"),
        @ApiResponse(code = 403, message = "Access denied"),
        @ApiResponse(code = 404, message = "The user doesn't exist"),
        @ApiResponse(code = 500, message = "Expired or invalid JWT token")})
    public String delete(@ApiParam("Username") @PathVariable String username) {
        userService.delete(username);
        return username;
    }

    @GetMapping(value = "/{username}")
    @PreAuthorize("hasAuthority('ADMIN_PRIVILEGE')")
    @ApiOperation(value = "${UserController.search}", response = UserResponseDTO.class)
    @ApiResponses(value = {
        @ApiResponse(code = 400, message = "Something went wrong"),
        @ApiResponse(code = 403, message = "Access denied"),
        @ApiResponse(code = 404, message = "The user doesn't exist"),
        @ApiResponse(code = 500, message = "Expired or invalid JWT token")})
    public UserResponseDTO search(@ApiParam("Username") @PathVariable String username) {
        return modelMapper.map(userService.search(username), UserResponseDTO.class);
    }

    @GetMapping(value = "/me")
    @PreAuthorize("hasAuthority('ADMIN_PRIVILEGE') or hasAuthority('USER_PRIVILEGE') or hasAuthority('CLIENT_PRIVILEGE')")
    @ApiOperation(value = "${UserController.me}", response = UserResponseDTO.class)
    @ApiResponses(value = {
        @ApiResponse(code = 400, message = "Something went wrong"),
        @ApiResponse(code = 403, message = "Access denied"),
        @ApiResponse(code = 500, message = "Expired or invalid JWT token")})
    public UserResponseDTO whoami(HttpServletRequest req) {
        return modelMapper.map(userService.whoami(req), UserResponseDTO.class);
    }

    @GetMapping("/refresh")
    @PreAuthorize("hasAuthority('ADMIN_PRIVILEGE') or hasAuthority('USER_PRIVILEGE') or hasAuthority('CLIENT_PRIVILEGE')")
    public String refresh(HttpServletRequest req) {
        return userService.refresh(req.getRemoteUser());
    }

    @IsAdmin
    @GetMapping("/isAdminAnnotation")
    public String isAdminAnnotation() {
        return "@interface IsAdmin";
    }

    @GetMapping("/isAdmin")
    @PreAuthorize("isAdmin()")
    public String isAdmin() {
        return "@PreAuthorize(\"isAdmin()\")";
    }

    @GetMapping("/username")
    @PreAuthorize("hasAuthority('ADMIN_PRIVILEGE') or hasAuthority('USER_PRIVILEGE') or hasAuthority('CLIENT_PRIVILEGE')")
    public String getCurrentUsername() {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal instanceof UserDetails) {
            return ((UserDetails) principal).getUsername();
        }
        if (principal instanceof Principal) {
            return ((Principal) principal).getName();
        }
        return String.valueOf(principal);
    }

    @PostAuthorize("hasPermission(returnObject, 'READ')")
    @GetMapping("/find/{id}")
    @ResponseBody
    public User findById(@PathVariable long id) {
        userRepository.findAll().stream().forEach(System.out::println);
        return userRepository.findById(id).orElseThrow(() -> new IllegalArgumentException("id "));
    }

    @PreAuthorize("hasPermission(#user, 'WRITE')")
    @PostMapping("/create")
    @ResponseStatus(HttpStatus.CREATED)
    @ResponseBody
    @ApiOperation(value = "${UserController.create}", response = UserResponseDTO.class)
    public User create(@RequestBody User user) {
        user.setId(null);
        return userRepository.save(user);
    }

    @PreAuthorize("@permissionEvaluator.hasPermission(authentication, #user, 'WRITE')")
    @PostMapping("/save")
    @ResponseStatus(HttpStatus.CREATED)
    @ResponseBody
    @ApiOperation(value = "${UserController.save}", response = UserResponseDTO.class)
    public UserResponseDTO save(@RequestBody User user) {
        user = userRepository.save(user);
        return modelMapper.map(user, UserResponseDTO.class);
    }

}
