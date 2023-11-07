import express from 'express';
import sqlite from 'sqlite';

import { asyncMiddleware } from './utils/asyncMiddleware';
import sleep from './utils/sleep';
import { generateRandomness, HMAC, KDF, checkPassword } from './utils/crypto';

const router = express.Router();
const dbPromise = sqlite.open('./db/database.sqlite')
var csrfToken = null;
const tokenMap = new Map();

// secret key for HMAC
const skey = "caia";

function render(req, res, next, page, title, errorMsg = false, result = null, csrfToken = null) {
  res.render(
    'layout/template', {
      page,
      title,
      loggedIn: req.session.loggedIn,
      account: req.session.account,
      errorMsg,
      result,
      //added
      csrfToken,
    }
  );
}

// checks account matches the session key
 function checkKey(account, key) {
   var str = account.username + account.hashedPassword + account.salt + account.profile + account.bitbars;
   var kprime = HMAC(skey, str);
   return (key == kprime);
 }

// makes a new session key from account data
function newKey(account) {
   var str = account.username + account.hashedPassword + account.salt + account.profile + account.bitbars;
   var k = HMAC(skey, str);
   return k;
}

// returns true if input text is alphanumeric only
function isAlphaNum(text) {
  if (text.match(/^[a-zA-Z0-9]+$/)) {
    return true;
  }
  return false;
}


router.get('/', (req, res, next) => {
  csrfToken = generateRandomness(); // generate a new csrf token
  tokenMap.set(req.session.account.username, csrfToken); // set the stored csrf token for this user
  render(req, res, next, 'index', 'Bitbar Home', false, null, csrfToken);
});


router.post('/set_profile', asyncMiddleware(async (req, res, next) => {
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };
  // CSRF STUFF
  if (!tokenMap.has(req.session.account.username)) { // checks to see if the user has a csrf token
    render(render(req, res, next, 'index', 'Bitbar Home'));
  }
  if (req.body.CSRFToken == null || (req.body.CSRFToken != tokenMap.get(req.session.account.username))) { // ensures csrf token in form matches stored token
    //CSRF token mismatch! force logout
    tokenMap.set(req.session.account.username, null);
    req.session.loggedIn = false;
    req.session.account = {};
    render(req, res, next, 'index', 'Bitbar Home', 'Logged out due to CSRF attack!');
  }
  csrfToken = generateRandomness(); // reset generated csrf token so that user can update profile again without reloading index page
  tokenMap.set(req.session.account.username, csrfToken); // reset stored csrf token

  req.session.account.profile = req.body.new_profile;

  const db = await dbPromise;
  const query = `UPDATE Users SET profile = ? WHERE username = "${req.session.account.username}";`;
  const result = await db.run(query, req.body.new_profile);
  render(req, res, next, 'index', 'Bitbar Home', false, null, csrfToken);
}));


router.get('/login', (req, res, next) => {
  // check if login is from right place
  if(req.session.key != null && req.session.loggedIn) {
  if(!checkKey(req.session.account, req.session.key)) {
    // force logout
    req.session.loggedIn = false;
    req.session.account = {};
    render(req, res, next, 'index', 'Bitbar Home', 'Logged out successfully!');
    return;
    }
  }
  render(req, res, next, 'login/form', 'Login', false, null, csrfToken);
});


router.get('/get_login', asyncMiddleware(async (req, res, next) => {
  if (!isAlphaNum(req.query.username)) { // if the username contains non-alphanumeric characters, reject
    render(req, res, next, 'login/form', 'Login', 'Invalid username. Only letters and numbers are allowed.');
    return;
  }

  const db = await dbPromise;
  const query = `SELECT * FROM Users WHERE username == "${req.query.username}";`;
  const result = await db.get(query);
  if(result) { // if this username actually exists
    if(checkPassword(req.query.password, result)) { // if password is valid
      await sleep(Math.random() * 2000);
      req.session.loggedIn = true;
      req.session.account = result;

      // make a new key when logging in
      req.session.key = newKey(req.session.account);
      render(req, res, next, 'login/success', 'Bitbar Home');
      return;
    // For GAMMA
     } else {
      await sleep(Math.random() * 2000);
     }
  }
  render(req, res, next, 'login/form', 'Login', 'This username and password combination does not exist!');
}));


router.get('/register', (req, res, next) => {
  render(req, res, next, 'register/form', 'Register');
});


router.post('/post_register', asyncMiddleware(async (req, res, next) => {

  if (!isAlphaNum(req.body.username)) { // if the username contains non-alphanumeric characters, reject
    render(req, res, next, 'register/form', 'Register', 'Invalid username. Only letters and numbers are allowed.');
    return;
  }

  const db = await dbPromise;
  let query = `SELECT * FROM Users WHERE username == "${req.body.username}";`;
  let result = await db.get(query);
  if(result) { // query returns results
    if(result.username === req.body.username) { // if username exists
      render(req, res, next, 'register/form', 'Register', 'This username already exists!');
      return;
    }
  }
  const salt = generateRandomness();
  const hashedPassword = KDF(req.body.password, salt);
  query = `INSERT INTO Users(username, hashedPassword, salt, profile, bitbars) VALUES(?, ?, ?, ?, ?)`;
  await db.run(query, [req.body.username, hashedPassword, salt, '', 100]);
  req.session.loggedIn = true;
  req.session.account = {
    username: req.body.username,
    hashedPassword,
    salt,
    profile: '',
    bitbars: 100,
  };
  // Make a key when creating a new account
  req.session.key = newKey(req.session.account);
  render(req, res, next,'register/success', 'Bitbar Home');
}));


router.get('/close', asyncMiddleware(async (req, res, next) => {
  // check close is coming from correct place
  if(!checkKey(req.session.account, req.session.key)) {
     req.session.loggedIn = false;
     req.session.account = {};
     render(req, res, next, 'index', 'Bitbar Home', 'Logged out successfully!');
     return;
  }

  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };
  const db = await dbPromise;
  const query = `DELETE FROM Users WHERE username == "${req.session.account.username}";`;
  await db.get(query);
  req.session.loggedIn = false;
  req.session.account = {};
  render(req, res, next, 'index', 'Bitbar Home', 'Deleted account successfully!');
}));


router.get('/logout', (req, res, next) => {
  req.session.loggedIn = false;
  req.session.account = {};
  req.session.key = null;
  render(req, res, next, 'index', 'Bitbar Home', 'Logged out successfully!');
});


router.get('/profile', asyncMiddleware(async (req, res, next) => {
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };
  // Check cookies are correct
  if(!checkKey(req.session.account, req.session.key)) {
     req.session.loggedIn = false;
     req.session.account = {};
     render(req, res, next, 'index', 'Bitbar Home', 'Logged out successfully!');
     return;
  }

  if(req.query.username != null) { // if visitor makes a search query
    const db = await dbPromise;
    const query = `SELECT * FROM Users WHERE username == "${req.query.username}";`;
    let result;
    try {
      result = await db.get(query);
    } catch(err) {
      result = false;
    }
    if(result) { // if user exists
      render(req, res, next, 'profile/view', 'View Profile', false, result);
    }
    else { // user does not exist
      var u = encodeURIComponent(req.query.username);
      render(req, res, next, 'profile/view', 'View Profile', `${u} does not exist!`, req.session.account);
    }
  } else { // visitor did not make query, show them their own profile
    render(req, res, next, 'profile/view', 'View Profile', false, req.session.account);
  }
}));


router.get('/transfer', (req, res, next) => {
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };
  // create csrfToken
  csrfToken = generateRandomness(); // generate a new csrf token
  tokenMap.set(req.session.account.username, csrfToken); // set the stored csrf token for this user
  render(req, res, next, 'transfer/form', 'Transfer Bitbars', false, {receiver:null, amount:null}, csrfToken);
});


router.post('/post_transfer', asyncMiddleware(async(req, res, next) => {
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };
  
  // Check cookies/ key
  if(!checkKey(req.session.account, req.session.key)){
     req.session.loggedIn = false;
     req.session.account = {};
     render(req, res, next, 'index', 'Bitbar Home', 'Logged out successfully!');
     return;
  }
  
  //CSRF MAP
  if (!tokenMap.has(req.session.account.username)) { // checks to see if the user has a csrf token
    render(req, res, next, 'transfer/form', 'Transfer Bitbars', 'Request not sent from transfer page.', {receiver:null, amount:null});
  }
  if (req.body.CSRFToken == null || (req.body.CSRFToken != tokenMap.get(req.session.account.username))) { // ensures csrf token in form matches stored token
    tokenMap.set(req.session.account.username, null);
    req.session.loggedIn = false;
    req.session.account = {};
    render(req, res, next, 'index', 'Bitbar Home', 'Logged out due to CSRF attack!');
    return;
  }
  csrfToken = null; // reset generated csrf token
  tokenMap.set(req.session.account.username, null); // reset stored csrf token

  // Check if username is alphanum
  if( !isAlphaNum(req.body.destination_username)) {
    csrfToken = generateRandomness(); // generate a new csrf token
    tokenMap.set(req.session.account.username, csrfToken); // set the stored csrf token for this user
    render(req, res, next, 'transfer/form', 'Transfer Bitbars', `User does not exist!`, {receiver:null, amount:null}, csrfToken);
    return;
  }

  // check if it is yourself/ remake token
  if(req.body.destination_username === req.session.account.username) {
    csrfToken = generateRandomness(); // generate a new csrf token
    tokenMap.set(req.session.account.username, csrfToken); // set the stored csrf token for this user
    render(req, res, next, 'transfer/form', 'Transfer Bitbars', 'You cannot send money to yourself!', {receiver:null, amount:null}, csrfToken);
    return;
  }

  const db = await dbPromise;
  let query = `SELECT * FROM Users WHERE username == "${req.body.destination_username}";`;
  const receiver = await db.get(query);
  if(receiver) { // if user exists
    const amount = parseInt(req.body.quantity);
    if(Number.isNaN(amount) || amount > req.session.account.bitbars || amount < 1) {
      csrfToken = generateRandomness(); // generate a new csrf token
      tokenMap.set(req.session.account.username, csrfToken); // set the stored csrf token for this user
      render(req, res, next, 'transfer/form', 'Transfer Bitbars', 'Invalid transfer amount!', {receiver:null, amount:null}, csrfToken);
      return;
    }

    req.session.account.bitbars -= amount;
     // NEW KEYYY
    req.session.key = newKey(req.session.account);

    query = `UPDATE Users SET bitbars = "${req.session.account.bitbars}" WHERE username == "${req.session.account.username}";`;
    await db.exec(query);
    const receiverNewBal = receiver.bitbars + amount;
    query = `UPDATE Users SET bitbars = "${receiverNewBal}" WHERE username == "${receiver.username}";`;
    await db.exec(query);
    render(req, res, next, 'transfer/success', 'Transfer Complete', false, {receiver, amount});
  } else { // user does not exist
    let q = req.body.destination_username;
    if (q == null) q = '';

    let oldQ;
    while (q !== oldQ) {
      oldQ = q;
      q = q.replace(/script|SCRIPT|img|IMG/g, '');
    }
    // remake token if failed
    csrfToken = generateRandomness(); // generate a new csrf token
    tokenMap.set(req.session.account.username, csrfToken); // set the stored csrf token for this user
    render(req, res, next, 'transfer/form', 'Transfer Bitbars', `User ${q} does not exist!`, {receiver:null, amount:null}, csrfToken);
  }
}));


router.get('/steal_cookie', (req, res, next) => {
  let stolenCookie = req.query.cookie;
  console.log('\n\n' + stolenCookie + '\n\n');
  render(req, res, next, 'theft/view_stolen_cookie', 'Cookie Stolen!', false, stolenCookie);
});

router.get('/steal_password', (req, res, next) => {
  let password = req.query.password;
  let timeElapsed = req.query.timeElapsed;
  console.log(`\n\nPassword: ${req.query.password}, time elapsed: ${req.query.timeElapsed}\n\n`);
  res.end();
});


module.exports = router;
