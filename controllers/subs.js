import User from '../models/user';

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

export const prices = async (req, res) => {
    const prices = await stripe.prices.list();
    res.json(prices.data.reverse());
};

export const createSubscription = async (req, res) => {
    try {
        const user = await User.findById(req.auth._id);

        const session = await stripe.checkout.sessions.create({
            mode: "subscription",
            payment_method_types: ["card"],
            line_items: [
              {
                price: req.body.priceId,
                quantity: 1,
              },
            ],
            customer: user.stripe_customer_id,
            success_url: process.env.STRIPE_SUCCESS_URL,
            cancel_url: process.env.STRIPE_CANCEL_URL,
        });
        console.log(session);
        res.json(session.url);
    } catch(error) {
        console.log(error);
    }
}

export const subscriptionStatus = async (req, res) => {
    try {
        const user = await User.findById(req.auth._id);

        const subscriptions = await stripe.subscriptions.list({
            customer: user.stripe_customer_id,
            status: 'all',
            expand: ['data.default_payment_method']
        });

        const updated = await User.findByIdAndUpdate(
            user._id,
            {
                subscriptions: subscriptions.data
            },
            {
                new: true
            }
        );

        res.json(updated);
    } catch(error) {
        console.log(error);
    }
}

export const subscriptions = async (req, res) => {
    try {
        const user = await User.findById(req.auth._id);

        const subscriptions = await stripe.subscriptions.list({
            customer: user.stripe_customer_id,
            status: 'all',
            expand: ['data.default_payment_method']
        });

        res.json(subscriptions);
    } catch (error) {
        console.log(error)
    }
}

export const customerPortal = async (req, res) => {
    try {
        const user = await User.findById(req.auth._id);
        const portalSession = await stripe.billingPortal.sessions.create({
            customer: user.stripe_customer_id,
            return_url: process.env.STRIPE_SUCCESS_URL
        });
        res.json(portalSession.url);
    } catch (error) {
        console.log(error);
    }
}