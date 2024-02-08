import crypto from "node:crypto";
import {Strategy as LocalStrategy} from "passport-local";
import {PrismaClient} from "@prisma/client";


/* scrypt 関連の定数値 */
const N = Math.pow(2, 17);
const maxmem = 144 * 1024 * 1024;
const keyLen = 192;
const saltSize = 64;

/**
 * Salt用のランダムバイト列生成
 * @return {Buffer}
 */
export const generateSalt = () => crypto.randomBytes(saltSize);

/**
 * パスワードハッシュ値計算
 * @param {String} plain
 * @param {Buffer} salt
 * @return {Buffer}
 */
export const calcHash = (plain, salt) => {
    const normalized = plain.normalize();
    const hash = crypto.scryptSync(normalized, salt, keyLen, {N, maxmem});
    if (!hash) {
        throw Error("ハッシュ計算エラー");
    }
    return hash;
};

/**
 * Passport.js の設定
 */
const config = (passport) => {
    const prisma = new PrismaClient();

    // データベースに問い合わせてユーザ名:パスワードをチェックして認証する部分
    passport.use(new LocalStrategy({
        usernameField: "name", passwordField: "pass"
    }, async (username, password, done) => {
        try {
            const user = await prisma.user.findUnique({
                where: {name: username}
            });
            if (!user) {
                // そんなユーザいないよの場合
                return done(null, false, {message: "ユーザ名かパスワードが違います1"});
            }
            const hashedPassword = calcHash(password, user.salt);
            if (!crypto.timingSafeEqual(user.pass, hashedPassword)) {
                // パスワードが違うよの場合
                return done(null, false, {message: "ユーザ名かパスワードが違います2"});
            }
            // 認証OK
            return done(null, user);
        } catch (e) {
            return done(e);
        }
    }));
    // セッションストレージにユーザデータを保存するときに呼ばれる
    passport.serializeUser((user, done) => {
        process.nextTick(() => {
            done(null, {id: user.id, name: user.name});
        });
    });
    // セッションストレージからデータを引っ張ってくるときに呼ばれる
    passport.deserializeUser((user, done) => {
        process.nextTick(() => {
            return done(null, user);
        });
    });
    // セッションストレージに messages を追加するミドルウェアとして関数を作って返す
    return (req, res, next) => {
        const messages = req.session.messages || [];
        res.locals.messages = messages;
        res.locals.hasMessages = !!messages.length;
        req.session.messages = [];
        next();
    };
};

export default config;