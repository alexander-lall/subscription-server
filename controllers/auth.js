import User from '../models/user';
import { validate } from 'email-validator';
import { hashPassword, comparePassword } from '../helpers/auth';
import jwt from 'jsonwebtoken';
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

export const register = async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Validation
        if(!name) {
            return res.json({
                error: 'Name is required'
            });
        }    
        if(!password || password.length < 6) {
            return res.json({
                error: 'Password should be 6 characters long'
            });
        }

        const exist = await User.findOne({ email });
        if(exist) {
            return res.json({
                error: "Email is taken"
            });
        } 
        if(!validate(email))  
        {
            return res.json({
                error: "Valid email address required"
            });
        } 

        // Hash password
        const hashedPassword = await hashPassword(password);

        // create stripe account
        const customer = await stripe.customers.create({
            email
        });

        try {
            const user = await new User({
                name, 
                email, 
                password: hashedPassword,
                stripe_customer_id: customer.id
            }).save();

            // Create signed token
            const token = jwt.sign(
                { _id: user._id }, 
                process.env.JWT_SECRET, 
                { expiresIn: '7d' }
            );

            const { password, ...rest } = user._doc;
            res.json({
                token,
                user: rest
            });
        } catch(error) {
            console.log(error)
        }
    } catch(error) {
        console.log(error);
    }
}

export const login = async (req, res) => {
    try{
        // Check email
        const user = await User.findOne({ email: req.body.email });
        if(!user) {
            return res.json({
                error: "Email and/or password invalid"
            });
        }

        // Check password
        const match = await comparePassword(req.body.password, user.password);
        if(!match) {
            return res.json({
                error: "Email and/or password invalid"
            });
        }
        // Create signed token
        const token = jwt.sign(
            { _id: user._id }, 
            process.env.JWT_SECRET, 
            { expiresIn: '7d' }
        );

        const { password, ...rest } = user._doc;
        res.json({
            token,
            user: rest
        });
    } catch(error) {
        console.log(error);
    }
}