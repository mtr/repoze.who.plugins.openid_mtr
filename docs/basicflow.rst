Sequence of an OpenID authentication process
--------------------------------------------

``repoze.who`` consists of several plugins which work together during the OpenID authentication sequence in the following way:

    1. The user enters a page which needs authentication
    2. The application raises an "401 Unauthorized" exception
    3. The ``IChallengeDecider`` plugin decides that the ``IChallenge`` plugin needs to be called
    4. The ``IChallenge`` plugin checks for the 401 and redirects the user to the URL defined in ``login_form_url``
    5. The user enters an OpenID into the login form and submits it. The URL given in the configuration option ``login_handler_url`` is POSTed to.
    6. The ``IIdentification`` plugin detects the URL given and checks if an openid is present in the POST data. If this is the case it copies the openid into the WSGI environment so that it's read later by the ``IChallenge`` plugin (which is called after the application has done it's part, which in this case is probably returning a ``404`` error because you don't need to implement the login handler as it's handled then by the challenge plugin)
    7. On egress with that ``404`` error the ``IChallengeDecider`` checks this time if an OpenID is present in the WSGI environment. If this is the case it will allow the ``IChallenge`` plugin to run
    8. The ``IChallenge`` plugin checks if the URL given in ``login_handler_path`` is active and if an OpenID is present in the environment. If this is the case it will start the OpenID discovery process using the Python OpenID library. It will return a WSGI application which will redirect the user to the OpenID provider.
    9. Coming back from the OpenID provider the user calls the URL given in ``login_handler_path`` again because this was the URL the plugin gave to the provider to redirect back to. The ``IIdentification`` plugin is called again on ingress and it checks again the URL to be correct and the result of the OpenID authentication (using the library). If everything was ok it stores the authenticated OpenID in the identity dict as ``repoze.who.plugins.openid.userid``. This is additionally remembered via the plugin given in the configuration option ``rememberer_name`` (usually this is ``auth_tkt``)
    10. The ``IAuthenticate`` plugin is called next and converts the found openid into a userid which is returned (``None`` means that no authentication took place). The dummy authenticator shipped with this plugin will simply copy the openid over as userid. Usually you should write your own plugin which might do some database lookup to find the correct user.

And this finishes the OpenID process.

