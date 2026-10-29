const express = require('express');
const axios = require('axios');
const path = require('path');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

const BASE_URL = process.env.MPESA_BASE_URL || 'https://sandbox.safaricom.co.ke';
const SHORTCODE = process.env.MPESA_SHORTCODE || '174379';
const PASSKEY = process.env.MPESA_PASSKEY;
const CALLBACK_URL = process.env.CALLBACK_URL;

app.use(express.json());

// Serve only the page, not the whole project folder
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Limit payment requests: 5 per minute per IP
const payLimiter = rateLimit({ windowMs: 60 * 1000, max: 5 });

app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        mode: BASE_URL.includes('sandbox') ? 'SANDBOX' : 'PRODUCTION',
        time: new Date().toISOString()
    });
});

app.post('/stkpush', payLimiter, async (req, res) => {
    try {
        const { phone: customerPhone, amount, reference: accountNumber } = req.body;

        if (!customerPhone || !amount) {
            return res.json({ success: false, error: 'Phone and amount required' });
        }

        const amt = Number(amount);
        if (!Number.isInteger(amt) || amt < 1 || amt > 150000) {
            return res.json({ success: false, error: 'Invalid amount' });
        }

        // Format phone to 2547XXXXXXXX
        let phone = String(customerPhone).replace(/\D/g, '');
        if (phone.startsWith('0') && phone.length === 10) {
            phone = '254' + phone.substring(1);
        } else if (phone.length === 9) {
            phone = '254' + phone;
        }
        if (!/^254\d{9}$/.test(phone)) {
            return res.json({ success: false, error: 'Invalid phone number' });
        }

        const token = await getToken();
        if (!token) {
            return res.json({ success: false, error: 'M-Pesa authentication failed' });
        }

        const timestamp = new Date().toISOString().replace(/[-:T.Z]/g, '').slice(0, 14);
        const password = Buffer.from(SHORTCODE + PASSKEY + timestamp).toString('base64');

        await axios.post(
            `${BASE_URL}/mpesa/stkpush/v1/processrequest`,
            {
                BusinessShortCode: SHORTCODE,
                Password: password,
                Timestamp: timestamp,
                TransactionType: 'CustomerPayBillOnline',
                Amount: amt,
                PartyA: phone,
                PartyB: SHORTCODE,
                PhoneNumber: phone,
                CallBackURL: CALLBACK_URL,
                AccountReference: accountNumber || 'Payment',
                TransactionDesc: 'Business Payment'
            },
            { headers: { Authorization: `Bearer ${token}` } }
        );

        res.json({
            success: true,
            data: {
                phone: phone,
                amount: `${amt} Ksh`,
                reference: accountNumber || '',
                note: 'Check your phone and enter your M-Pesa PIN.'
            }
        });
    } catch (error) {
        console.error('Payment error:', error.response?.data || error.message);
        res.json({
            success: false,
            error: error.response?.data?.errorMessage || error.message
        });
    }
});

// Safaricom posts the payment result here
app.post('/callback', (req, res) => {
    const cb = req.body?.Body?.stkCallback;
    if (cb) {
        if (cb.ResultCode === 0) {
            const items = cb.CallbackMetadata?.Item || [];
            const get = (name) => items.find((i) => i.Name === name)?.Value;
            console.log('PAID:', {
                checkoutId: cb.CheckoutRequestID,
                receipt: get('MpesaReceiptNumber'),
                amount: get('Amount'),
                phone: get('PhoneNumber')
            });
            // TODO: save to a database
        } else {
            console.log('FAILED/CANCELLED:', cb.CheckoutRequestID, cb.ResultDesc);
        }
    }
    res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
});

async function getToken() {
    try {
        const auth = Buffer.from(
            `${process.env.MPESA_CONSUMER_KEY}:${process.env.MPESA_CONSUMER_SECRET}`
        ).toString('base64');
        const response = await axios.get(
            `${BASE_URL}/oauth/v1/generate?grant_type=client_credentials`,
            { headers: { Authorization: `Basic ${auth}` } }
        );
        return response.data.access_token;
    } catch (error) {
        console.error('Token error:', error.message);
        return null;
    }
}

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));