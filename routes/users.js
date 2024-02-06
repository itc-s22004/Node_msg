const router = require("express").Router();
const passport = require("passport");
const LocalStrategy = require("passport-local");
const {PrismaClient} = require("@prisma/client");
const prisma = new PrismaClient();
const scrypt = require("../util/scrypt");
const {timingSafeEqual} = require("node:crypto");
const {check, validationResult} = require("express-validator");

// 認証処理の実装
passport.use(new LocalStrategy(
    {usernameField: "name", passwordField: "password"},
    async (username, password, cb) => {
      try {
        const user = await prisma.user.findUnique({
          where: {name: username}
        });
        if (!user) {
          // 指定されたユーザがデータベースにない場合
          return cb(null, false, {message: "ユーザ名かパスワードが違います"});
        }
        // あらためてリクエストに含まれるパスワードのハッシュ値を計算する
        const hashedPassword = scrypt.calcHash(password, user.salt);
        // 計算したハッシュ値と、データベースに保存されているハッシュ値の比較
        if (!timingSafeEqual(user.password, hashedPassword)) {
          // 2つのハッシュ値を比較して異なっていた場合(パスワードが間違っている)
          return cb(null, false, {message: "ユーザ名かパスワードが違います"});
        }
        // ユーザもパスワードも正しい場合
        return cb(null, user);
      } catch (e) {
        return cb(e);
      }
    }
));

// ユーザ情報をセッションに保存するルールの定義
passport.serializeUser((user, done) => {
  process.nextTick(() => {
    done(null, {id: user.id, name: user.name});
  });
});

// セッションからユーザ情報を復元するルールの定義
passport.deserializeUser((user, done) => {
  process.nextTick(() => {
    return done(null, user);
  });
});

router.get("/login", (req, res, next) => {
  const data = {
    title: "Users/Login",
    content: "名前とパスワードを入力ください"
  };
  res.render("users/login", data);
});

/**
 * passport.js の関数を利用して認証処理をおこなう。
 */
router.post("/login", passport.authenticate("local", {
  successReturnToOrRedirect: "/",
  failureRedirect: "/users/login",
  failureMessage: true,
  keepSessionInfo: true
}));

/**
 * ログアウト処理
 */
router.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/users/login");
  });
});

/**
 * 新規登録のフォームを表示するだけのページ
 */
router.get("/signup", (req, res, next) => {
  const data = {
    title: "Users/Signup",
    name: "",
    email: "",
    age: 20
  };
  res.render("users/signup", data);
});

/**
 * 新規登録をする処理
 */
router.post("/signup", [
  check("name", "NAME は必ず入力してください。").notEmpty(),
  check("password", "PASSWORD は必ず入力してください。").notEmpty(),
  check("email", "EMAIL はメールアドレスを入力してください。").isEmail(),
  check("age", "AGE は整数で入力してください。").isInt()
], async (req, res, next) => {
  const result = validationResult(req);

  // 入力値チェックで問題があれば登録処理はしないで再入力を求める
  if (!result.isEmpty()) {
    const messages = result.array();
    const data = {
      title: "Users/Signup",
      name: req.body.name,
      email: req.body.email,
      age: req.body.age,
      messages,
    };
    res.render("users/signup", data);
    return;
  }
  // 入力値チェックに問題がなければデータ登録
  const {name, password, email, age} = req.body;
  const salt = scrypt.generateSalt();
  const hashedPassword = scrypt.calcHash(password, salt);
  await prisma.user.create({
    data: {
      name,
      password: hashedPassword,
      salt,
      email,
      age: +age,
    }
  });
  res.redirect("/users/login");
});

module.exports = router;


// import express from "express";
// import passport from "passport";
// import {check, validationResult} from "express-validator";
// import {calcHash, generateSalt} from "../util/auth.js";
// import {PrismaClient} from "@prisma/client";
//
// const router = express.Router();
// const prisma = new PrismaClient();
//
// /* GET users listing. */
// router.get('/', function(req, res, next) {
//   res.send("hello")
// });
//
// router.get("/login", (req, res, next) => {
//   const data = {
//
//   }
//   res.render("users/login", data)
// });
//
// router.post("/login", passport.authenticate("local", {
//   successReturnToOrRedirect: "/",
//   failureRedirect: "/users/login",
//   failureMessage: true,
//   keepSessionInfo: true
// }));
//
// router.get("/signup", (req, res, next) => {
//   const data = {
//     title: "ユーザ新規登録",
//     name: "",
//     errors: []
//   };
//   res.render("users/signup", data);
// });
//
// /**
//  * ユーザ新規登録処理
//  */
// router.post("/signup", [
//   check("name", "名前の入力は必須です").notEmpty(),
//   check("pass", "パスワードの入力は必須です").notEmpty(),
// ], async (req, res, next) => {
//   const result = validationResult(req);
//   if (!result.isEmpty()) {
//     // 入力チェックでだめだった場合
//     const errors = result.array();
//     const data = {
//       title: "ユーザ新規登録",
//       name: req.body.name,
//       errors,
//     };
//     res.render("users/signup", data);
//     return;
//   }
//   // 入力チェックOKだったらこの先に進む。
//   const {name, pass} = req.body;
//   const salt = generateSalt();
//   const hashedPassword = calcHash(pass, salt);
//   await prisma.user.create({
//     data: {
//       name,
//       pass: hashedPassword,
//       salt
//     }
//   });
//   res.redirect("/users/login");
// });
//
// export default router;