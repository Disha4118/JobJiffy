const express=require('express')
const router=express.Router();
const {body}= require('express-validator');
const usercontroller=require('../controller/user.controller');

router.post('/login',
    body('email').isEmail().withMessage('Invalid email'),
    usercontroller.login
)
router.post('/signup',
    body('email').isEmail().withMessage('Invalid email'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
    body('name').notEmpty().withMessage('Name is required'),
    body('phone').notEmpty().withMessage('Phone number is required'),
    usercontroller.signup
)

module.exports=router;
