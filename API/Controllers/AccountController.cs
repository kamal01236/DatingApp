using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTO;
using API.Entities;
using API.Interface;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _dataContext;
        private readonly ITokenService _tokenService;
        public AccountController(DataContext dataContext, ITokenService tokenService)
        {
            _tokenService = tokenService;
            _dataContext = dataContext;
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
        {
            if (await UserExists(registerDto.UserName)) return BadRequest("UserName is taken");

            using var hmac = new HMACSHA512();
            var user = new AppUser()
            {
                UserName = registerDto.UserName,
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                PasswordSalt = hmac.Key
            };

            
            _dataContext.Users.Add(user);
            await _dataContext.SaveChangesAsync();
            return new UserDto
            {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }
        private async Task<bool> UserExists(string username)
        {
            return await _dataContext.Users.AnyAsync(x => x.UserName == username.ToLower());
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
        {
            var usr = await _dataContext.Users.SingleOrDefaultAsync(x => x.UserName == loginDto.Username);
            if (usr == null) return Unauthorized("Invalid User");

            using var hmac = new HMACSHA512(usr.PasswordSalt);
            var passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));
            for (int i = 0; i < passwordHash.Length; i++)
            {
                if (passwordHash[i] != usr.PasswordHash[i]) return Unauthorized("Invalid Password");
            }
            return new UserDto
            {
                Username = usr.UserName,
                Token = _tokenService.CreateToken(usr)
            };
        }
    }
}