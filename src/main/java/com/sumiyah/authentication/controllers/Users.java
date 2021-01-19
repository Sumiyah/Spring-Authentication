package com.sumiyah.authentication.controllers;

import javax.servlet.http.HttpSession;
import javax.validation.Valid;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import com.sumiyah.authentication.models.User;
import com.sumiyah.authentication.services.UserService;
import com.sumiyah.authentication.validator.UserValidator;

@Controller
public class Users {

private final UserService userService;

private final UserValidator userValidator;
    
    public Users(UserService userService, UserValidator userValidator) {
        this.userService = userService;
        this.userValidator = userValidator;
    }
    
    @RequestMapping("/")
    public String redirect() {
    	return "redirect:/registration";
    }
    
    @RequestMapping("/registration")
    public String registerForm(@ModelAttribute("user") User user) {
        return "registrationPage.jsp";
    }
    @RequestMapping("/login")
    public String login() {
        return "loginPage.jsp";
    }
    
    @RequestMapping(value="/registration", method=RequestMethod.POST)
    public String registerUser(@Valid @ModelAttribute("user") User user, BindingResult result, HttpSession session) {
        // if result has errors, return the registration page (don't worry about validations just now)
    	userValidator.validate(user, result);
    	if(result.hasErrors()) {
    		return "registrationPage.jsp";
    	} else {
    	// else, save the user in the database, save the user id in session, and redirect them to the /home route
    		this.userService.registerUser(user);
    		session.setAttribute("user", user.getId());
    		return "redirect:/home";
    	}
    }
    
    @RequestMapping(value="/login", method=RequestMethod.POST)
    public String loginUser(@RequestParam("email") String email, @RequestParam("password") String password, Model model, HttpSession session) {
        // if the user is authenticated, save their user id in session
    	if (this.userService.authenticateUser(email, password)) {
    		User user = this.userService.findByEmail(email);
    		session.setAttribute("user",user.getId() );
    		return "redirect:/home";
    	} else {
    		// else, add error messages and return the login page
    		model.addAttribute("error", "Invalid Credentials! Try again..");
    		return "loginPage.jsp";
    	}
    }
    
    @RequestMapping("/home")
    public String home(HttpSession session, Model model) {
        // get user from session, save them in the model and return the home page
//    	session.getAttribute("user");
    	model.addAttribute("user", this.userService.findUserById((Long)session.getAttribute("user")));
    	return "homePage.jsp";
    }
    
    @RequestMapping("/logout")
    public String logout(HttpSession session) {
        // invalidate session
//    	session.setAttribute("user", null);
    	session.invalidate();
        // redirect to login page
    	return "redirect:/login";
    }
}
