# Armaxis

## Analysis

The problem gives you access to two services: the Armaxis portal, and an email app. The email app states that your email address is `test@email.htb`, meaning that it will display emails sent to that address. The Armaxis portal contains only a login form with the option to register to the service. The source is available for consultation.

## Solution

We start by registering an account on the system using the `test@email.htb` and proceeding to login into the system. We will notice that there isn't a lot to do here. By Analyzing the code and finding the [`database.js`](Source/challenge/database.js), we discover that a default user with the email `admin@armaxis.htb` has been registered with a password too complex to be brute-forced. Going further into the code, more specifically into the [`routes/index.js`](Source/challenge/routes/index.js) we will find endpoints related to resetting passwords. By carefully inspecting the code we will notice that one of the endpoints requests the password reset and generates a reset token that is emailed to the user. We then check the code for applying the reset and notice that it does not check if the reset token was generated for the user at hand, only if the token is valid in general. That means we can request a password reset for the user we created, receive the reset token via email, and use it to reset the `admin`'s password to something we know. So first we do:

```
POST /reset-password/request
{
    'email': 'test@email.htb'
}
```

Checking the email app, we will get a token for the password reset (in this example `b5c78cda1bc44986168daefd78464255`), which we will use as follows:

```
POST /reset-password/
{
    'email': 'admin@armaxis.htb',
    'password': 'banana',
    'token': 'b5c78cda1bc44986168daefd78464255'
}
```

This will respond with a status 200. Now we can proceed to login as the `admin` user. We will notice a new page is accessible to us: "Dispatch Weapon". It takes a name, price, note, and email. The note is specifically said to be parsed markdown. Conveniently, there is a file [`markdown.js`](Source/challenge/markdown.js) in the code. By analyzing the code, we will notice that the `parseMarkdown` function will look for the regex `/\!\[.*?\]\((.*?)\)/g`, which would be similar to `![LABEL](URL)`, which is the syntax for adding images in markdown with a `!` prepended. We will notice that the code finds these formats and replaces the URL part with an inline `base64` representation of the image, which would stop the markdown from reaching to an external domain every time it loads. However, the way the code downloads the image from the URL is through the command `curl -L ${url}`, which means that it can be used to perform command injection. We now dispatch a weapon with the a note with the format `![Something](; cat /flag.txt)` and setting the user email to `admin@armaxis.htb`. By going back to the homepage, we will see that we have a new weapon listed with the note field saying `Embedded Image`. By looking at the source code for the image, we will find the URL `data:image/*;base64,SFRCe0ZBS0VfRkxBR19GT1JfVEVTVElOR30K`. Translating the content from `base64` we get the flag `HTB{FAKE_FLAG_FOR_TESTING}`.