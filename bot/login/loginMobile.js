const { spawn } = require("child_process");
const logger = require("../../utils/log");
const fs = require('fs').promises;
const getCookie = require('./Fblogin');

// Hàm đọc JSON loại bỏ BOM nếu có
async function readJSON(path) {
    const raw = await fs.readFile(path, 'utf8');
    return JSON.parse(raw.replace(/^\uFEFF/, ''));
}

async function loginMobile() {
    const config = await readJSON('./config.json');

    if (!config.facebookAccount || !config.facebookAccount.email || !config.facebookAccount.password) {
        throw new Error('Không tìm thấy email hoặc password trong config!');
    }

    const facebookAccount = {
        email: config.facebookAccount.email,
        password: config.facebookAccount.password,
        '2FASecret': config.facebookAccount['2FASecret'] || '',
        i_user: config.facebookAccount.i_user || ''
    };

    logger('Đang tiến hành đăng nhập để làm mới...', '[ AUTO LOGIN ]');

    const result = await getCookie({
        username: facebookAccount.email,
        password: facebookAccount.password,
        twofactor: facebookAccount['2FASecret'] || '0',
        i_user: facebookAccount.i_user || null
    });

    if (result.status === false) {
        throw new Error(result.message);
    }

    return result;
}

module.exports = loginMobile;
