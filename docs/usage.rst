Configuration
=============

.. Module: repoze.who.plugins.openid.identitification

The OpenID plugin is configured like all the other ``repoze.who`` plugins via
the ``who.ini`` file (or what the name of it happens to be according to your
main ``.ini`` file.

Here is an example of the openid-plugin-section::


          [plugin:openid]

          use = repoze.who.plugins.openid:make_identification_plugin

          store = file 
          store_file_path = %(here)s/sstore
          openid_field = openid
          came_from_field = came_from
          error_field = error
          session_name = beaker.session
          login_form_url = /login_form
          login_handler_path = /do_login
          logout_handler_path = /logout
          logged_in_url = /success
          logged_out_url = /logout_success
          rememberer_name = auth_tkt

A more complete example will be given below. 

Configuration options
---------------------

Here is a list of all possible configuration options and there possible values:

.. describe:: store

    Defines which OpenID store implementation to use. Possible values are
    ``mem``, ``file`` and ``sql``. Depending on what you choose here you need 
    to give additional values such as a file path or sql connection string.

    ``mem`` means to use a RAM based store for OpenID associations. No further
    configuration is possible here.

    ``file`` means to use a file based store for OpenID associations. You need
    to give the path to the file being used as ``store_file_path`` option.

    ``sql`` means to use an SQL database for storing OpenID associations. You
    need at least give a connection string as ``store_sql_connstring`` configuration
    option. Additionally you can choose which tables to use. The defaults are
    ``oid_associations`` and ``oid_nonces`` but they can be configured by the 
    configuration options ``store_sql_associations_table`` and ``store_sql_nonces_table``
    respectively. Check the OpenID library documentation for more info on
    these tables and how to use the SQL store.
    
    .. warning:: The SQL implementation is not working at the moment.

.. describe:: openid_field

    You define here in which field in the request coming from a login form the
    OpenID of the user is stored. Default is ``openid``.
    
.. describe:: came_from_field

    ``came_from_field`` defines in which field in a request coming from the login form the URL is stored to which to redirect after successful authentication. The default is ``came_from``.
    
    .. warning:: This is not really tested and might actually not work due to
                 the redirections of the OpenID process itself. Better use ``logged_in_url`` for this. 
    
.. describe:: error_field

    This directive defines in which field in the WSGI environment OpenID errors will be written should they occur. The default is ``error``.
    
.. describe:: session_name

    OpenIDs requires a session for the whole login process (basically from sending the user to the OpenID provider to the provider redirecting back and checking the result). The default is to use a cookie internally. 
    
    If you are using your own session middleware anyway and it's providing
    a dictionary interface in an WSGI environment variable then you can 
    configure this to be used by providing the name of this variable as ``session_name``.
    
    Example::
    
        session_name = beaker.session

.. describe:: login_form_url

    This directive defines under which path the login page is to be found. This needs to be configured so the challenge plugin can redirect to it.
    
    The login page is supposed to ask the user for the OpenID to be used to login which then is supposed to be stored in a field named as configured with ``openid_field``. 
    

.. describe:: login_handler_path

    This configuration defines the URL the login form POSTs it's data to.
    You need to define this because the OpenID process will also use this URL
    to know when an OpenID authentication process is active as the OpenID provider will redirect back to this URL. The plugin will then intercept this
    redirect and parse the results.
    
    You don't really have to write a view for this URL as it's just there to
    be intercepted by this plugin.
    
    In case of a login success the user will be redirected to the URL defined
    in ``logged_in_url``. In case of an error the login form will be displayed
    again.

.. describe:: logout_handler_path

    In order to be able to log a user out again you have to give a path 
    which you send the user to. This URL again does not need to be implemented
    as a view but only serves as marker for this plugin to know.
    
    After the logout has happened the user will be redirect to the URL defined
    in ``logged_out_url``.

.. describe:: logged_in_url

    Store the URL in here to which the user should be redirected after a 
    successful login. You need to define this and you need to implement the
    view for it.

.. describe:: logged_out_url

    Store the URL in here to which the user should be redirected after a 
    successful logout. You need to define this and you need to implement the
    view for it.

.. describe:: rememberer_name

    Place the name of the identification plugin here which is used to remember
    a successful authentication. You can e.g. configure the ``auth_tkt`` 
    plugin as done in the ``repoze.who`` example and just put this in here::
    
        rememberer_name = auth_tkt
        
    The result is that the openid of the user will be stored as cookie via the
    ``auth_tkt`` plugin. This plugin also makes it somewhat sure that the 
    value is not plain text in the cookie but encrypted at least somewhat.
    
    Other possibilities are here to e.g. use a session for this you have
    anyway. Check the ``repoze.who`` documentation on how to write a
    rememberer plugin.
    
    
The challenge decider
---------------------

In order to trigger the OpenID process the challenge plugin needs to know when
to really start it. Usually this needs to be done if an OpenID is present in the request. Per default the challenger is only called for ``Unauthorized`` responses from the application. In order to also trigger it for requests containing the field defined in ``openid_field`` you also have to configure a different Challengde Decider in your ``who.ini``::

    [general]
    challenge_decider = repoze.who.plugins.openid.classifiers:openid_challenge_decider

    
Complete example
----------------
    
In order to show how all the plugins work together here is a complete ``who.ini``:

.. literalinclude:: who.ini
   :language: none



