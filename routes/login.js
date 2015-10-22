var bcrypt = require('bcrypt');

    exports.userCheck = function (req, res, next) {
        if (req.session.user){
             next();
        }
        else{
             res.redirect("/")
        }
    };

    exports.signup = function(req, res, next) {
            req.getServices()
              .then(function(services){
                var input = JSON.parse(JSON.stringify(req.body));
                var data = {
                    Username: input.username,
                    Password: input.password,
                    User_role: 'read-only'

                };
                bcrypt.genSalt(10, function(err, salt) {
                    bcrypt.hash(input.password, salt, function(err, hash) {
                        // Store hash in your password DB.
                        data.Password = hash;
                      });
                  });
                var loginDataService = services.loginDataService;
                loginDataService.signup(data)
                    .then(function(results){
                        res.redirect('/?status=user_created');
                      })
                            .catch(function(err){
                                next(err);
                        });
            });
        };

    exports.adminSignup = function(req, res, next) {
        req.getServices()
          .then(function(services){
            var input = JSON.parse(JSON.stringify(req.body));
            var data = {
                Username: input.username,
                Password: input.password,
                User_role: input.key
            };
            admin = 'admin';
            var loginDataService = services.loginDataService;
            loginDataService.adminSignup(data)
                .then(function(results){
            //bcrypt the password===
            bcrypt.genSalt(10, function(salt) {
                bcrypt.hash(input.password, salt, function(hash) {
                        data.Password = hash;
                         if(input.key == admin){
                           res.redirect('/?status=user_created');
                         }
                         else{
                           res.redirect('/admin_signup');
                          }
                    })
                });
            });
        });
    };

exports.userLogin = function(req, res, next) {
    req.getServices()
    .then(function(services){
        var input = JSON.parse(JSON.stringify(req.body));
        var username = input.username;
        var loginDataService = services.loginDataService;
        loginDataService.login(username)
            .then(function(results){
            var user = results[0];

            bcrypt.compare(input.password, user.Password,function(err, pass) {
                if (pass) {
                    req.session.user = username;
                    req.session.role =  user.User_role;
                    return res.redirect("/home")
                } else {
                    return res.redirect('/');

                }
            });
        })
      })
      .catch(function(err){
          next(err);
      });
};
