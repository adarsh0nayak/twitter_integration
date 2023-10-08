import express from "express";
import morgan from "morgan";
import dotEnv from "dotenv";
import randomString from "randomstring";
import axios from "axios";
import crypto from "crypto";
import base64url from "base64url";

const app = express();
app.use(express.json());
app.use(morgan("dev"));
dotEnv.config({ path: ".env" });

/**initializing globals */
global.user_twitter_map = [];

/**twitter urls and redirect urls */
let callbackUrl = `http://localhost:3000/twitter/callback`;
let authUrl = `https://twitter.com/i/oauth2/authorize?`;
let tokenUrl = `https://api.twitter.com/2/oauth2/token?`;
let postTweetApi = `https://api.twitter.com/2/tweets`;


/**twitter configuration */
const client_id = process.env.TWITTER_CLIENT_ID;
const client_secret = process.env.TWITTER_CLIENT_SECRET;
const codeVerifier = randomString.generate(128);
const base64Digest = crypto.createHash("sha256").update(codeVerifier).digest("base64");
const codeChallenge = base64url.fromBase64(base64Digest);
const scopes = `tweet.read%20tweet.write%20users.read%20offline.access`;
let clientCredential = `${client_id}:${client_secret}`;
clientCredential = Buffer.from(clientCredential).toString("base64");

/**all the routes go down here */
app.get("/", (req, res) => {
  res.status(200).send("Welcome to twitter integration app");
  return;
});

app.get("/twitter/callback", async (req, res) => {
  try{
    let { state, code } = req.query;

    if (!state || !code) {
    res.redirect("/");
    return;
    }

    let payload = {
      grant_type: "authorization_code",
      code: code,
      redirect_uri: callbackUrl,
      code_verifier: codeVerifier,
    };
  
    let freshTokenUrl = tokenUrl;
    for (let [key, value] of Object.entries(payload)) {
      freshTokenUrl += `${key}=${value}&`;
    }

    let headers = {
      Authorization: `Basic ${clientCredential}`,
      "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
    };

    let tokenResult;
    let accessToken;
    let expiryInMill;

    try {
      tokenResult = await axios.post(freshTokenUrl, {}, { headers });
      accessToken = tokenResult.data.access_token;
      expiryInMill = tokenResult.data.expires_in * 1000;
    } catch (error) {
      console.log(error.message);
      res.redirect("/");
      return;
    }

    global.user_twitter_map.push({
      id: state,
      accessToken,
      expiresIn: new Date().getTime() + expiryInMill,
    });

    res.status(200).send("SUCCESS");
    return;

}catch(error){
  console.log(error.message);
  res.redirect('/');
  return;
}
});

app.post("/post/tweet", async (req, res) => {
  try {
    let requestBody = JSON.parse(JSON.stringify(req.body));
    let userId = req.query.user;
    let userInfo = await checkUserToken(userId);
    if (userInfo.code !== 1) {
      res.status(302).send(authorize(userId));
      return;
    }

    let headers = {
      Authorization: `Bearer ${userInfo.data.accessToken}`,
      "Content-Type": "application/json",
    };

    try{
      /**posting a tweet */
      let postTweetResult = await axios.post(postTweetApi,{ "text": requestBody.text },{ headers });
      
      res.status(200).send({ msg: "SUCCESS", tweetId: postTweetResult.data.id });
      return;
    }catch(error){
      console.log(error.message);
      res.status(500).send(error.data);
      return;
    }

  } catch (error) {
    console.log(error);
    res.status(500).send({ msg: error.message });
    return;
  }
});

function checkUserToken(userId) {
  return new Promise(async (resolve, reject) => {
    try {
      let userInfo = global.user_twitter_map.find(({ id }) => id === userId);
      if (!userInfo) {
        resolve({ code: 2, data: "User not found in the memory" });
        return;
      }

      let isUserExpired =
        new Date(userInfo.expiresIn).getTime() <= new Date().getTime();
      if (isUserExpired) {
        resolve({ code: 2, data: "User token expired" });
        return;
      }

      resolve({ code: 1, data: userInfo });
      return;
    } catch (error) {
      console.log(error.message);
      reject({ code: -1, data: error });
      return;
    }
  });
}

function authorize(userId) {
  return `${authUrl}response_type=code&scope=${scopes}&client_id=${client_id}&redirect_uri=${callbackUrl}&state=${userId}&code_challenge=${codeChallenge}&code_challenge_method=S256`;
  
}

app.listen(3000, (err) => {
  console.log("Listening on port 3000");
  return;
});
