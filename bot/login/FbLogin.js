const deviceID = require('uuid');
const adid = require('uuid');
const { TOTP } = require("totp-generator"); 
const axios = require("axios");
const logger = require("../../utils/log");

const ANDROID_DEVICES = [
    { model: "Pixel 6", build: "SP2A.220505.002" },
    { model: "Pixel 5", build: "RQ3A.210805.001.A1" },
    { model: "Samsung Galaxy S21", build: "G991USQU4AUDA" },
    { model: "OnePlus 9", build: "LE2115_11_C.48" },
    { model: "Xiaomi Mi 11", build: "RKQ1.200826.002" }
];

function getRandomDevice() {
    const device = ANDROID_DEVICES[Math.floor(Math.random() * ANDROID_DEVICES.length)];
    return {
        userAgent: `Dalvik/2.1.0 (Linux; U; Android 11; ${device.model} Build/${device.build})`,
        device
    };
}

async function getCookie({ username, password, twofactor = '0', _2fa, i_user }) {
    try {
        const androidDevice = getRandomDevice();
        const device_id = deviceID.v4();
        const family_device_id = deviceID.v4();
        const machine_id = randomString(24);
        const form = {
            adid: adid.v4(),
            email: username,
            password: password,
            format: 'json',
            device_id: device_id,
            cpl: 'true',
            family_device_id: family_device_id,
            locale: 'en_US',
            client_country_code: 'US',
            credentials_type: 'device_based_login_password',
            generate_session_cookies: '1',
            generate_analytics_claim: '1',
            generate_machine_id: '1',
            currently_logged_in_userid: '0',
            irisSeqID: 1,
            try_num: "1",
            enroll_misauth: "false",
            meta_inf_fbmeta: "NO_FILE",
            source: 'login',
            machine_id: machine_id,
            fb_api_req_friendly_name: 'authenticate',
            fb_api_caller_class: 'com.facebook.account.login.protocol.Fb4aAuthHandler',
            api_key: '882a8490361da98702bf97a021ddc14d',
            access_token: '350685531728|62f8ce9f74b12f84c123cc23437a4a32',
            advertiser_id: adid.v4(),
            device_platform: 'android',
            app_version: '392.0.0.0.66',
            network_type: 'WIFI'
        };

        form.sig = encodesig(sort(form));
        
        const options = {
            url: 'https://b-graph.facebook.com/auth/login',
            method: 'post',
            data: form,
            transformRequest: [(data) => require('querystring').stringify(data)],
            headers: {
                'content-type': 'application/x-www-form-urlencoded',
                'x-fb-friendly-name': form["fb_api_req_friendly_name"],
                'x-fb-http-engine': 'Liger',
                'user-agent': androidDevice.userAgent,
                'x-fb-connection-type': 'WIFI',
                'x-fb-net-hni': '',
                'x-fb-sim-hni': '',
                'x-fb-device-group': '5120',
                'x-tigon-is-retry': 'False',
                'x-fb-rmd': 'cached=0;state=NO_MATCH',
                'x-fb-request-analytics-tags': 'unknown',
                'authorization': `OAuth ${form.access_token}`,
                'accept-language': 'en-US,en;q=0.9',
                'x-fb-client-ip': 'True',
                'x-fb-server-cluster': 'True'
            }
        };

        return new Promise((resolve) => {
            axios.request(options).then(async(response) => {
                try {
                    const appstate = response.data.session_cookies.map(cookie => ({
                        key: cookie.name,
                        value: cookie.value,
                        domain: cookie.domain,
                        path: cookie.path
                    }));

                    if (i_user) {
                        appstate.push({
                            key: 'i_user',
                            value: i_user,
                            domain: '.facebook.com',
                            path: '/'
                        });
                    }
                    const tokenOptions = {
                        url: `https://api.facebook.com/method/auth.getSessionforApp?format=json&access_token=${response.data.access_token}&new_app_id=275254692598279`,
                        method: 'get',
                        headers: {
                            'user-agent': androidDevice.userAgent,
                            'x-fb-connection-type': 'WIFI',
                            'authorization': `OAuth ${response.data.access_token}`
                        }
                    };

                    const tokenV6D7Response = await axios.request(tokenOptions);
                    
                    const result = {
                        appstate: appstate,
                        access_token: response.data.access_token,
                        access_token_eaad6v7: tokenV6D7Response.data.access_token,
                        device_info: {
                            model: androidDevice.device.model,
                            user_agent: androidDevice.userAgent
                        }
                    };

                    resolve(result);
                } catch (e) {
                    logger(`Login error: ${e.message}`, '[ LOGIN ERROR ]');
                    resolve({
                        status: false,
                        message: "Please enable 2FA and try again!"
                    });
                }
            }).catch(async (error) => {
                try {
                    const data = error.response.data.error.error_data;
                    let twoFactorCode;
                    if (_2fa && _2fa !== "0") {
                        twoFactorCode = _2fa;
                    } else if (twofactor && twofactor !== "0") {
                        try {
                            logger('Đang xử lý 2FA', '[ AUTO LOGIN ]');
                            const cleanSecret = decodeURI(twofactor).replace(/\s+/g, '').toUpperCase(); 
                            const { otp } = TOTP.generate(cleanSecret);
                            twoFactorCode = otp;
                        } catch (e) {
                            resolve({
                                status: false,
                                message: 'Invalid 2FA secret key'
                            });
                            return;
                        }
                    } else {
                        resolve({
                            status: false,
                            message: 'Please provide 2FA code or secret key'
                        });
                        return;
                    }

                    const twoFactorForm = {
                        ...form,
                        twofactor_code: twoFactorCode,
                        encrypted_msisdn: "",
                        userid: data.uid,
                        machine_id: data.machine_id || machine_id,
                        first_factor: data.login_first_factor,
                        credentials_type: "two_factor"
                    };
                    twoFactorForm.sig = encodesig(sort(twoFactorForm));
                    options.data = twoFactorForm;
                    
                    try {
                        const twoFactorResponse = await axios.request(options);
                        const appstate = twoFactorResponse.data.session_cookies.map(cookie => ({
                            key: cookie.name,
                            value: cookie.value,
                            domain: cookie.domain,
                            path: cookie.path
                        }));
                        if (i_user) {
                            appstate.push({
                                key: 'i_user',
                                value: i_user,
                                domain: '.facebook.com',
                                path: '/'
                            });
                        }
                        const tokenOptions = {
                            url: `https://api.facebook.com/method/auth.getSessionforApp?format=json&access_token=${twoFactorResponse.data.access_token}&new_app_id=275254692598279`,
                            method: 'get',
                            headers: {
                                'user-agent': androidDevice.userAgent,
                                'x-fb-connection-type': 'WIFI',
                                'authorization': `OAuth ${twoFactorResponse.data.access_token}`
                            }
                        };

                        const tokenV6D7Response = await axios.request(tokenOptions);

                        const result = {
                            appstate: appstate,
                            access_token: twoFactorResponse.data.access_token,
                            access_token_eaad6v7: tokenV6D7Response.data.access_token,
                            device_info: {
                                model: androidDevice.device.model,
                                user_agent: androidDevice.userAgent
                            }
                        };

                        resolve(result);
                    } catch (requestError) {
                        logger(`Lỗi request 2FA: ${requestError.message}`, '[ 2FA ERROR ]');
                        console.log(requestError.response?.data);
                        resolve({
                            status: false,
                            message: 'Failed to authenticate with 2FA code. Please try again.'
                        });
                    }

                } catch (twoFactorError) {
                    logger(`Lỗi xử lý 2FA: ${twoFactorError.message}`, '[ 2FA ERROR ]');
                    resolve({
                        status: false,
                        message: 'Two-factor authentication process failed. Please check your credentials and try again.'
                    });
                }
            });
        });
    } catch (e) {
        logger(`Lỗi chung: ${e.message}`, '[ ERROR ]');
        return {
            status: false,
            message: 'Incorrect username or password. Please check your credentials!'
        };
    }
}

function randomString(length) {
    length = length || 10;
    let char = 'abcdefghijklmnopqrstuvwxyz';
    let result = char.charAt(Math.floor(Math.random() * char.length));
    for (let i = 0; i < length - 1; i++) {
        result += 'abcdefghijklmnopqrstuvwxyz0123456789'.charAt(Math.floor(36 * Math.random()));
    }
    return result;
}

function encodesig(string) {
    let data = '';
    Object.keys(string).forEach((key) => {
        data += `${key}=${string[key]}`;
    });
    return md5(data + '62f8ce9f74b12f84c123cc23437a4a32');
}

function md5(string) {
    return require('crypto').createHash('md5').update(string).digest('hex');
}

function sort(string) {
    const sortedKeys = Object.keys(string).sort();
    let sortedData = {};
    for (const key of sortedKeys) {
        sortedData[key] = string[key];
    }
    return sortedData;
}

module.exports = getCookie;