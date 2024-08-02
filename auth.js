// middleware/authMiddleware.js

function isAuthenticated(req, res, next) {
    if (req.session && req.session.login_user) {
      return next(); // User is authenticated, proceed to the next middleware or route handler
    } else {
      res.redirect('/'); // Redirect to login page if user is not authenticated
    }
  }
  
  module.exports = isAuthenticated;
  