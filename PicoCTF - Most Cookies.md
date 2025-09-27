# PicoCTF - Most Cookies

# Introduction

Do you like cookies? I love cookies. Let’s learn how a cookie is baked inside a Flask web app (*￣3￣)╭

This PicoCTF challenge was fun to navigate, as most of it involved researching how Flask generates session cookies. I thought I’d need to make a brute-forcing script at one point, but open-source tools clutched up 😤.

I’ll be walking through my thought process and the resources I found that assisted with the solution!

Challenge Link: [https://play.picoctf.org/practice/challenge/177](https://play.picoctf.org/practice/challenge/177)

### Context

<img width="967" height="543" alt="image" src="https://github.com/user-attachments/assets/47087364-4690-4f93-9a15-3c227fd9bc1d" />

The challenge provides us with a Python file and a website. Based on the description, I figured that we’d be dealing with Flask session cookies, so I did some research for the context needed to find the flag:

Flask - Web app framework for Python. For session management, it defaults to signed cookies. These cookies are not encrypted, so we can crack open the contents of a Flask session cookie.

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

Upon opening the website, there’s not much to see at first. Entering `snickerdoodle` as written will give us some cryptic message without much meaning.

<img width="740" height="519" alt="image 1" src="https://github.com/user-attachments/assets/911f6ab3-63c9-4367-81c1-869861e72fab" />

<img width="732" height="423" alt="image 2" src="https://github.com/user-attachments/assets/dde86aa5-da76-4435-b72e-7ed841da4897" />

Since this challenge is dealing with Flask cookies, I open up Burp Suite to check out what that cookie may look like (you could also use your web browser’s inspect element feature).

Upon inspecting the `POST` request to `/search` when we input `snickerdoodle`, a session cookie is set, and it looks like a Flask signed cookie from our research beforehand.

A similar cookie can be seen with our initial `GET` to `/`.

<img width="1497" height="457" alt="image 3" src="https://github.com/user-attachments/assets/693d319e-5fc9-451d-a9f2-fcd6e8ba80ca" />

Knowing that Flask signed cookies are Base64 encoded, I ran the cookies through Cyberchef to see if I could read out any data.

We can see a key-value pair of the cookie names we typed in: `snickerdoodle`

<img width="1530" height="640" alt="image 4" src="https://github.com/user-attachments/assets/b609cf78-5c98-4bc9-a73b-0f01f319d819" />

<img width="1524" height="619" alt="image 5" src="https://github.com/user-attachments/assets/d6603024-396a-43dd-b09b-4c937a8c2bb8" />

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

Entering `admin` into the cookie search will cause an error, so we will need to craft a session cookie and give it to `/display` to meet the `if check == "admin":` statement.

Knowing that Flask signed cookies can be cracked, I did some digging and found an amazing article written by Luke Paris on how Flask signed cookies can be cracked.

[Baking Flask cookies with your secrets](https://blog.paradoxis.nl/defeating-flasks-session-management-65706ba9d3ce)

This website by Bordergate provides us with tools and more context on how we could crack Flask signed cookies ourselves.

[Flask Session Cookies < BorderGate](https://www.bordergate.co.uk/flask-session-cookies/)

The following Python tool can be used to unsign Flask signed cookies and lead us to the secret behind how these cookies are “baked”.

[flask-unsign](https://pypi.org/project/flask-unsign/)

Like I do for most things, I overthink. Seeing an array of values that’s taken randomly to be the secret value used to sign cookies, I thought we had to brute-force the website by creating a custom script.

After using the `Flask-unsign` tool on the web app, I realized that the random secret value is determined when the web app starts and not during the runtime of the web app. So theoretically, the secret would be one of these strings in `cookie_names[]`.

<img width="1064" height="223" alt="image 6" src="https://github.com/user-attachments/assets/6fb1906c-2863-454c-8e1e-fff89082dc9f" />

<img width="1149" height="285" alt="image 7" src="https://github.com/user-attachments/assets/94a311f7-cacd-4c9b-9048-f9ef333b087d" />

As you can see, I pulled multiple session cookies from the website and unsign them using `Flask-unsign`, and the final secret key is still `'peanut butter'`

After finding the secret, we are able to use it to sign our own Flask signed cookie.

We can then use this cookie in a request to `/display` and that should get us the flag.

<img width="836" height="81" alt="image 8" src="https://github.com/user-attachments/assets/7c71b877-992c-4f5c-8f9e-83534769babc" />

Using curl, we set the cookie with `-b` and also set `-L` because of the redirect that happens from `/search` to `/display`.

<img width="961" height="195" alt="image 9" src="https://github.com/user-attachments/assets/92b2a296-925c-40f9-b2ef-76e53c1f9de0" />

Booyah! Flag acquired! (o゜▽゜)o☆ 

# Conclusion

Different web apps handle session management differently. When your session cookies can be easily predicted or calculated, that’s when a vulnerability arise. Although we had access to the web app source code, it is still possible to crack Flask sign cookies in real environments. Just like user passwords, the secret used to signed Flask cookies can be brute-forced if not strong or complex. Along with using a strong secret key, session management should be moved server-side. Never trust the client!

Thanks for joining me on today’s baking show. Hopefully your new Flask cookies are tasty! 😋
