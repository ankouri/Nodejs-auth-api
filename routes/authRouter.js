const router = require("express").Router();
const authController = require("../controllers/authController");

//REGISTER ROUTER
router.post('/register', authController.handleRegister);

//ACTIVATION ACCOUNT ROUTER
router.get('/activate/:token', authController.handleActivation)

//RESET PASSWORD ROUTER
router.post('/forgot', authController.handleForgetPassword)
router.get('/reset/:id', authController.handleResetPassword)
router.get('/forgot/:token', authController.handleGotoReset)

//LOGIN ROUTER RETURN USER OBJECT OR NULL
router.post('/login', authController.handleLogin);

//LOGOUT ROUTER SET USER TO NULL
router.get('/logout', authController.handleLogout);
module.exports = router;
