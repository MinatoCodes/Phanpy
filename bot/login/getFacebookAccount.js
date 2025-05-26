module.exports = async function getFacebookAccount(configPath = './config.json') {
    const config = await readJSON(configPath);
    if (!config.facebookAccount || !config.facebookAccount.email || !config.facebookAccount.password) {
        throw new Error('Không tìm thấy email hoặc password trong config!');
    }
    return {
        email: config.facebookAccount.email,
        password: config.facebookAccount.password,
        '2FASecret': config.facebookAccount['2FASecret'] || '',
        i_user: config.facebookAccount.i_user || ''
    };
};