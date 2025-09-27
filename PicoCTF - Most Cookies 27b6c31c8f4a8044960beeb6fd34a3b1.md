# PicoCTF - Most Cookies

# Introduction

Do you like cookies? I love cookies. Let’s learn how a cookie is baked inside a Flask web app (*￣3￣)╭

This PicoCTF challenge was fun to navigate thru as most of it was researching on how Flask generates session cookies. I thought I’d need to make a brute-forcing script at one point but open-source tools clutched up 😤.

I’ll be walking through my thought process and the resources I found that assisted with the solution!

Challenge Link: [https://play.picoctf.org/practice/challenge/177](https://play.picoctf.org/practice/challenge/177)

### Context

![image.png](PicoCTF%20-%20Most%20Cookies%2027b6c31c8f4a8044960beeb6fd34a3b1/image.png)

The challenge provides us a python file and a website. Based on the description, I figured that we’d be dealing with flask session cookies so I did some research for the context needed to find the flag:

Flask - Web app framework for Python. For session management, it defaults to signed cookies. These cookies are not encrypted so we may be able to crack open the contents of a Flask session cookie.

How are Flask session cookies generated?

1. Key-Value pair of a cookie is serialized as a JSON string
    - `{'cookie': 'valuehere'}`
2. JSON string + timestamp is Base64 encoded together
3. A sha1 HMAC is generated using a secret key + base64 result of JSON string & timestamp
    - `sha1HMAC(secret, base64(JSON + timestamp))`
4. The HMAC signature is appended to the Base64 string
5. And thus, a Flask session cookie is generated

Example: `eyJ2ZXJ5X2F1dGgiOiJzbmlja2VyZG9vZGxlIn0.aNdq0w.HLlC4CclK_8hrnXPxf6LcQ6_V5o`

- *Note: `.` (periods) separate the key-value pair, timestamp, and HMAC signature*

## Challenge

Upon opening the website, there’s not much to see at first. Entering in `snickerdoodle` as written well give us some cryptic message without much meaning.

![image.png](PicoCTF%20-%20Most%20Cookies%2027b6c31c8f4a8044960beeb6fd34a3b1/image%201.png)

![image.png](PicoCTF%20-%20Most%20Cookies%2027b6c31c8f4a8044960beeb6fd34a3b1/image%202.png)

Since this challenge is dealing with Flask cookies, I open up Burp Suite to check out what that cookie may look like (you could also use your web browser’s inspect element feature).

Upon inspecting the `POST` request to `/search` when we inputted `snickerdoodle`, a session cookie is set and it looks like a Flask signed cookie from our research beforehand.

A similar cookie can be seen with our initial `GET` to `/`.

![image.png](PicoCTF%20-%20Most%20Cookies%2027b6c31c8f4a8044960beeb6fd34a3b1/image%203.png)

Knowing that Flask signed cookies are Base64 encoded, I ran the cookies through Cyberchef to see if I can read out any data.

We can see a key-value pair of the cookie names we typed in: `snickerdoodle`

![image.png](PicoCTF%20-%20Most%20Cookies%2027b6c31c8f4a8044960beeb6fd34a3b1/image%204.png)

![image.png](PicoCTF%20-%20Most%20Cookies%2027b6c31c8f4a8044960beeb6fd34a3b1/image%205.png)

Let’s take a look at the Python file provided to see if we can get more context.

```python
from flask import Flask, render_template, request, url_for, redirect, make_response, flash, session
import random
app = Flask(__name__)
flag_value = open("./flag").read().rstrip()
title = "Most Cookies"
cookie_names = ["snickerdoodle", "chocolate chip", "oatmeal raisin", 
"gingersnap", "shortbread", "peanut butter", "whoopie pie", "sugar",
"molasses", "kiss", "biscotti", "butter", "spritz", "snowball", "drop", 
"thumbprint", "pinwheel", "wafer", "macaroon", "fortune", "crinkle", "icebox", 
"gingerbread", "tassie", "lebkuchen", "macaron", "black and white", "white chocolate macadamia"]
app.secret_key = random.choice(cookie_names)

@app.route("/")
def main():
	if session.get("very_auth"):
		check = session["very_auth"]
		if check == "blank":
			return render_template("index.html", title=title)
		else:
			return make_response(redirect("/display"))
	else:
		resp = make_response(redirect("/"))
		session["very_auth"] = "blank"
		return resp

@app.route("/search", methods=["GET", "POST"])
def search():
	if "name" in request.form and request.form["name"] in cookie_names:
		resp = make_response(redirect("/display"))
		session["very_auth"] = request.form["name"]
		return resp
	else:
		message = "That doesn't appear to be a valid cookie."
		category = "danger"
		flash(message, category)
		resp = make_response(redirect("/"))
		session["very_auth"] = "blank"
		return resp

@app.route("/reset")
def reset():
	resp = make_response(redirect("/"))
	session.pop("very_auth", None)
	return resp

@app.route("/display", methods=["GET"])
def flag():
	if session.get("very_auth"):
		check = session["very_auth"]
		if check == "admin":
			resp = make_response(render_template("flag.html", value=flag_value, title=title))
			return resp
		flash("That is a cookie! Not very special though...", "success")
		return render_template("not-flag.html", title=title, cookie_name=session["very_auth"])
	else:
		resp = make_response(redirect("/"))
		session["very_auth"] = "blank"
		return resp

if __name__ == "__main__":
	app.run()
```

From this Python file, we can infer many things:

- This is the source code to the challenge web app
- `app.secret_key` may be the secret used to sign Flask cookies
    - `random.choice(cookie_names)` = The secret could be any of the values in the `cookie_names` array
- `if check == "admin":` says that the website will print the flag if our session cookie is `very_auth: admin`
- The session cookie will affect how the `/display` page will be presented to us

Entering in `admin` into the cookie search will cause an error so we will need to craft a session cookie and give it to `/display` to meet the `if check == "admin":` statement.

Knowing that Flask signed cookies can be cracked, I did some digging and found an amazing article written by Luke Paris on how Flask signed cookies can be cracked.

[Baking Flask cookies with your secrets](https://blog.paradoxis.nl/defeating-flasks-session-management-65706ba9d3ce)

This website by bordergate provides us with tools and more context into how we could crack Flask signed cookies ourselves.

[Flask Session Cookies < BorderGate](https://www.bordergate.co.uk/flask-session-cookies/)

The following Python tool can be used to unsign Flask signed cookies and lead us to the secret behind how these cookies are “baked”.

[flask-unsign](https://pypi.org/project/flask-unsign/)

Like I do for most things, I overthink. Seeing an array of values that’s taken randomly to be the secret value used to sign cookies, I thought we had to brute-force the website through creating a custom script.

After using the `Flask-unsign` tool on the web app, I realized that the random secret value is determined on when the web app starts and not during runtime of the web app. So theoretically, the secret would be one of these strings in `cookie_names[]`.

![image.png](PicoCTF%20-%20Most%20Cookies%2027b6c31c8f4a8044960beeb6fd34a3b1/image%206.png)

![image.png](PicoCTF%20-%20Most%20Cookies%2027b6c31c8f4a8044960beeb6fd34a3b1/image%207.png)

As you can see, I pulled multiple session cookies from the website and unsigned them using `Flask-unsign` and the final secret key is still `'peanut butter'`

After finding the secret, we are able to use it to sign our own Flask signed cookie.

We can then use this cookie in a request to `/display` and that should get us the flag.

![image.png](PicoCTF%20-%20Most%20Cookies%2027b6c31c8f4a8044960beeb6fd34a3b1/image%208.png)

Using curl, we set the cookie with `-b` and also set `-L` because of the redirect that happens from `/search` to `/display`.

![image.png](PicoCTF%20-%20Most%20Cookies%2027b6c31c8f4a8044960beeb6fd34a3b1/image%209.png)

Booyah! Flag acquired! (o゜▽゜)o☆ 

# Conclusion

Different web apps handle session management differently. When your session cookies can be easily predicted or calculated, that’s when a vulnerability arise. Although we had access to the web app source code, it is still possible to crack Flask sign cookies in real environments. Just like user passwords, the secret used to signed Flask cookies can be brute-forced if not strong or complex. Along with using a strong secret key, session management should be moved server-side. Never trust the client!

Thanks for joining me on today’s baking show, hopefully your new Flask cookies are tasty! 😋