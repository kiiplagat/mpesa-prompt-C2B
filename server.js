const express = require('express');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(express.static('.'));

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        server: 'M-Pesa Business Payments',
        time: new Date().toISOString()
    });
});

// Pay to Business endpoint (what your HTML is calling)
app.post('/pay-to-business', async (req, res) => {
    console.log('💼 Business Payment Request:', req.body);
    
    try {
        const { customerPhone, amount, accountNumber } = req.body;
        
        if (!customerPhone || !amount) {
            return res.json({
                success: false,
                error: 'Phone and amount required'
            });
        }
        
        // Format phone
        let phone = customerPhone.replace(/\D/g, '');
        if (phone.startsWith('0') && phone.length === 10) {
            phone = '254' + phone.substring(1);
        }
        
        console.log(`📱 ${phone} paying ${amount} Ksh, Account: ${accountNumber}`);
        
        // Get M-Pesa token
        const token = await getToken();
        if (!token) {
            return res.json({
                success: false,
                error: 'M-Pesa authentication failed. Check .env credentials.'
            });
        }
        
        // Prepare STK request
        const timestamp = new Date().toISOString()
            .replace(/[-:T.Z]/g, '')
            .slice(0, 14);
        
        const shortcode = "174379"; // Sandbox
        const passkey = "bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919";
        const password = Buffer.from(shortcode + passkey + timestamp).toString('base64');
        
        const requestData = {
            BusinessShortCode: shortcode,
            Password: password,
            Timestamp: timestamp,
            TransactionType: "CustomerPayBillOnline",
            Amount: amount,
            PartyA: phone,
            PartyB: shortcode,
            PhoneNumber: phone,
            CallBackURL: "https://webhook.site",
            AccountReference: accountNumber || "Payment",
            TransactionDesc: "Business Payment"
        };
        
        console.log('📤 Sending to M-Pesa...');
        
        const response = await axios.post(
            'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
            requestData,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            }
        );
        
        console.log('✅ M-Pesa Response:', response.data.ResponseDescription);
        
        res.json({
            success: true,
            message: 'STK Push sent successfully!',
            details: {
                from: customerPhone,
                to: 'Business Account',
                amount: `${amount} Ksh`,
                account: accountNumber,
                checkoutId: response.data.CheckoutRequestID,
                note: phone === '254708374149' 
                    ? 'Check Sandbox dashboard (PIN: 174379)'
                    : 'STK sent to phone'
            }
        });
        
    } catch (error) {
        console.error('❌ Payment Error:', error.response?.data || error.message);
        res.json({
            success: false,
            error: error.response?.data?.errorMessage || error.message,
            message: 'Payment failed. Check credentials and try again.'
        });
    }
});

// Get M-Pesa token
async function getToken() {
    try {
        const auth = Buffer.from(`${process.env.MPESA_CONSUMER_KEY}:${process.env.MPESA_CONSUMER_SECRET}`).toString('base64');
        
        const response = await axios.get(
            'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials',
            { headers: { 'Authorization': `Basic ${auth}` } }
        );
        
        return response.data.access_token;
    } catch (error) {
        console.log('❌ Token Error:', error.message);
        return null;
    }
}

// Start server
app.listen(PORT, () => {
    console.log(`
🏢 ===== BUSINESS PAYMENT SERVER ===== 🏢
✅ Server: http://localhost:${PORT}
📞 Endpoint: POST /pay-to-business
🔧 Mode: SANDBOX
📱 Test phone: 254708374149
🔑 PIN: 174379 (in sandbox dashboard)
🏢 =================================== 🏢
    `);
});