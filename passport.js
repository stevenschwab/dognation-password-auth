const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");
const helper = require("../helpers/helper");

// Set up the Passport strategy:
passport.use(
  new LocalStrategy(function (username, password, cb) {
    helper.findByUsername(username, async function (err, user) {
      if (err) {
        return cb(err);
      }
      if (!user) {
        return cb(null, false);
      }

      const matchedPassword = await bcrypt.compare(password, user.password);

      if (!matchedPassword) {
        return cb(null, false);
      }
      return cb(null, user);
    });
  })
);
// Serialize a user
passport.serializeUser((user, done) => {
  done(null, user.id);
});
// Deserialize a user
passport.deserializeUser((user) => {
  helper.findById(user.id, function (err, done) {
    if (err) {
      return done(err);
    }
    done(null, user);
  });
});