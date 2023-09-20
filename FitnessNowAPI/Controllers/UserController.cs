using FitnessNowAPI.Context;
using FitnessNowAPI.Helpers;
using FitnessNowAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Text;
using System.Text.RegularExpressions;

namespace FitnessNowAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _authContext;

        public UserController(AppDbContext authContext)
        {
            _authContext = authContext;
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if (userObj == null)
            {
                return BadRequest();
            }

            var user = await _authContext.Users.FirstOrDefaultAsync(x => x.Username == userObj.Username && x.Password ==  userObj.Password);
            if (user == null) 
            {
                return NotFound(new { Message = "User Not Found!" });
            }

            return Ok( new { Message = "Login Success!" });
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if(userObj == null)
            {
                return BadRequest();
            }

            //Check username
            if (await CheckUserNameExistsAsync(userObj.Username)) 
            {
                return BadRequest(new { Message = "That username already exists!" });
            }

            //Check Email
            if (await CheckEmailExistsAsync(userObj.Email))
            {
                return BadRequest(new { Message = "That email already exists!" });
            }

            //Check password strength
            var pass = CheckPasswordStrength(userObj.Password);
            if(!string.IsNullOrEmpty(pass)) 
            {
                return BadRequest(new { Message = pass.ToString() });
            }

            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "User";
            userObj.Token = "";

            await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();
            return Ok(new 
            { 
                Message = "User Registered!" 
            });
        }

        private Task<bool> CheckUserNameExistsAsync(string userName) 
        {
            return _authContext.Users.AnyAsync(x => x.Username == userName);
        }

        private Task<bool> CheckEmailExistsAsync(string email)
        {
            return _authContext.Users.AnyAsync(x => x.Email == email);
        }

        private string CheckPasswordStrength(string password)
        {
            StringBuilder sb = new StringBuilder();
            if(password.Length < 8) 
            {
                sb.Append("Minimum password length should be 8 characters" + Environment.NewLine);
            }

            if (!(Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]") && Regex.IsMatch(password, "[0-9]"))) 
                sb.Append("Password should be Alphanumeric" + Environment.NewLine);
            if (!Regex.IsMatch(password, "[<,>,@,!,#,$,%,^,&,*,(,),_,+,\\[,\\],{,},?,:,;,|,',\\,.,/,~,`,-,=]"))
                sb.Append("Password should contain special characters" + Environment.NewLine);

            return sb.ToString();
        }
    }
}
