import base64
import hmac
import logging

from openid.consumer import consumer
from openid.extensions import sreg
from openid.store import memstore, filestore, sqlstore
from pylons.controllers.util import Response as PylonsResponse
from repoze.who.interfaces import IChallenger, IIdentifier, IAuthenticator
from webob import Request
from zope.interface import implements


try:
    import cPickle as pickle
except ImportError:
    import pickle
try:
    from hashlib import sha1
except ImportError:
    import sha as sha1

class Response(PylonsResponse):
    def signed_cookie(self, name, data, secret=None, **kwargs):
        """Save a signed cookie with ``secret`` signature
        
        Saves a signed cookie of the pickled data. All other keyword
        arguments that ``WebOb.set_cookie`` accepts are usable and
        passed to the WebOb set_cookie method after creating the signed
        cookie value.

        This implementation fixes the problem when
        base64.encodestring, originally used, returned an
        endline-partitioned string.
        """
        pickled = pickle.dumps(data, pickle.HIGHEST_PROTOCOL)
        sig = hmac.new(secret, pickled, sha1).hexdigest()
        self.set_cookie(name, sig + base64.b64encode(pickled), **kwargs)


class OpenIdIdentificationPlugin(object):
    """The repoze.who OpenID plugin
    
    This class contains 3 plugin types and is thus implementing
    IIdentifier, IChallenger and IAuthenticator.
    (check the `repoze.who documentation <http://static.repoze.org/bfgdocs/>`_
    for what all these plugin types do.)
    
    """
    implements(IChallenger, IIdentifier, IAuthenticator)
    
    #log = logging.getLogger('auth')
    log = logging.getLogger('.'.join(__name__.split('.')[:-1]))
    
    def __init__(self,
                 store, 
                 openid_field, 
                 error_field='',
                 store_file_path='',
                 db_connection_factory=None,
                 session_name='',
                 login_handler_path='',
                 logout_handler_path='',
                 login_form_url='',
                 logged_in_url='',
                 logged_out_url='',
                 came_from_field='',
                 rememberer_name='',
                 sql_associations_table='',
                 sql_nonces_table='',
                 sql_connstring='',
                 md_provider_name='openid_md',
                 sreg_required=None,
                 sreg_optional=None,
                 ):

        self.rememberer_name = rememberer_name
        self.login_handler_path = login_handler_path
        self.logout_handler_path = logout_handler_path
        self.login_form_url = login_form_url
        self.session_name = session_name
        self.error_field = error_field
        self.came_from_field = came_from_field
        self.logged_out_url = logged_out_url
        self.logged_in_url = logged_in_url
        
        # for the SQL store
        self.db_connection_factory = db_connection_factory
        self.db_connection = self.db_connection_factory()
        self.sql_associations_table = sql_associations_table
        self.sql_nonces_table = sql_nonces_table
        
        self.md_provider_name = md_provider_name
        self.sreg_required = sreg_required or []
        self.sreg_optional = sreg_optional or ['email','fullname', 'nickname']

        # set up the store
        if store==u"file":
            self.store = filestore.FileOpenIDStore(store_file_path)
        elif store==u"mem":
            self.store = memstore.MemoryStore()
        elif store==u"sql":
            # TODO: This does not work as we need a connection, not a string
            #self.store = sqlstore.SQLStore(sql_connstring,
            #                               sql_associations_table,
            #                               sql_connstring)
            self.store = sqlstore.MySQLStore(self.db_connection)
            
        self.openid_field = openid_field
            
    def _get_rememberer(self, environ):
        rememberer = environ['repoze.who.plugins'][self.rememberer_name]
        return rememberer
    def _get_md_provider(self, environ):
        md_provider = environ['repoze.who.plugins'].get(self.md_provider_name)
        return md_provider

    def get_consumer(self,environ):
        session = environ.get(self.session_name, {})
        return consumer.Consumer(session, self.store)

    def _redirect_to(self, environ, target_url=None, cookies=[]):
        """Redirect to target_url if given, or to came_from if
        defined.  Otherwise, redirect to standard logged_in_url page.
        """
        if target_url is None:
            target_url = Request(environ).params.get(self.came_from_field, '') \
                         or self.logged_in_url
            
        response = Response()
        
        # Redirect.
        response.status = 302           # HTTP Status: Found.
        response.location = target_url
        
        # Add cookie headers, if requested.
        for (cookie_identity, cookie_data, cookie_parameters) in cookies:
            response.signed_cookie(cookie_identity, cookie_data,
                                   **cookie_parameters)
            
        environ['repoze.who.application'] = response    

    # IIdentifier
    def identify(self, environ):
        """This method is called when a request is incoming.
        
        If credentials are found, the returned identity mapping will
        contain an arbitrary set of key/value pairs.
        
        Return None to indicate that the plugin found no appropriate
        credentials.
        
        After the challenge has been called we might get here a
        response from an openid provider.
        """
        request = Request(environ)
        
        # First test for logout as we then don't need the rest.
        if request.path == self.logout_handler_path:
            self._logout_and_redirect(environ)
            return None
        
        # Then we check that we are actually on the URL which is
        # supposed to be the url to return to (login_handler_path in
        # configuration) this URL is used for both: the answer for the
        # login form and when the openid provider redirects the user
        # back.
        elif request.path != self.login_handler_path:
            return None
        
        # In the case we are coming from the login form we should have
        # an openid in the request, entered by the user.
        return self._handle_login(environ, request)

    def _handle_login(self, environ, request):
        open_id = request.params.get(self.openid_field, None)
        
        self.log.debug('checking openid results for: "%s".', open_id)

        if open_id is not None:
            open_id = open_id.strip()

        identity = {}
        
        # We don't do anything with the openid we found ourselves but
        # we put it in here to tell the challenge plugin to initiate
        # the challenge.
        environ['repoze.whoplugins.openid.openid'] = open_id
        identity['repoze.whoplugins.openid.openid'] = open_id
        
        # This part now is for the case when the openid provider
        # redirects the user back.  We should find some openid
        # specific fields in the request.
        mode = request.params.get("openid.mode", None)
        if mode == "id_res":
            info = self.get_consumer(environ).complete(request.params,
                                                       request.url)
            
            # Remove this so that the challenger is not triggered
            # again.
            del environ['repoze.whoplugins.openid.openid']
            
            if info.status == consumer.SUCCESS:
                identity = self._handle_successful_response(environ, identity,
                                                            open_id, info)
                
            # TODO: Do we have to check for more failures and such?
            
        elif mode == "cancel":
            # Cancel is a negative assertion in the OpenID protocol,
            # which means the user did not authorize correctly.
            environ['repoze.whoplugins.openid.error'] \
                    = 'OpenID authentication failed.'
            
        return identity

    def _handle_successful_response(self, environ, identity, open_id, info):
        self.log.info('openid request successful for : %s ', open_id)
        
        target_url = None
        extra_cookies = []
        
        # Parse the SREG information.
        try:
            sreg_resp = sreg.SRegResponse.fromSuccessResponse(info)
        except AttributeError, err:
            self.log.warn("Failure during SReg parsing: %s", err)
            sreg_resp = None
            
        if sreg_resp:
            # Store the user metadata.
            self.log.debug("User info received: %s", sreg_resp.data)
            user_data = dict()
            for field in self.sreg_required + self.sreg_optional:
                sreg_val = sreg_resp.get(field)
                if sreg_val:
                    user_data[field] = sreg_val
                    
            if user_data:
                md = self._get_md_provider(environ)
                if md:
                    (status, target_url, extra_cookies) \
                        = md.authenticate_or_register_user( \
                        info.identity_url,
                        user_data,
                        environ,
                        identity)
                    
                    if status is True:
                        # User existed and this should be considered a
                        # successful login.
                        pass
                    
                    elif status is None:
                        # User did not exist, but a temporary user has
                        # been created.
                        identity = None
                        
                    elif status is False:
                        # Error.  Perhaps another user is already
                        # registered with the same OpenID?
                        self.log.error("Unable to register user")
                        identity = None

                else:
                    self.log.warn("No metadata provider %s found",
                                  self.md_provider_name)
        else:
            self.log.warn("No user metadata received!")
            # Store the id for the authenticator.
            identity['repoze.who.plugins.openid.userid'] = info.identity_url
            
        # If target_url is None, then redirect to came_from or the
        # login success page.
        self._redirect_to(environ, target_url, extra_cookies)
        
        return identity

    def _logout_and_redirect(self, environ):
        response = Response()
        
        # Set forget headers.
        for a, v in self.forget(environ, {}):
            response.headers.add(a, v)
            
        response.status = 302
        response.location = self.logged_out_url
        environ['repoze.who.application'] = response
        
        return None                # Unset authentication information.
    
    # IIdentifier
    def remember(self, environ, identity):
        """remember the openid in the session we have anyway"""
        rememberer = self._get_rememberer(environ)
        r = rememberer.remember(environ, identity)
        return r

    # IIdentifier
    def forget(self, environ, identity):
        """forget about the authentication again"""
        rememberer = self._get_rememberer(environ)
        return rememberer.forget(environ, identity)

    # IChallenge
    def challenge(self, environ, status, app_headers, forget_headers):
        self.store.conn = self.db_connection_factory()
        
        return self._challenge(environ, status, app_headers, forget_headers)
        
    def _challenge(self, environ, status, app_headers, forget_headers):
        """the challenge method is called when the ``IChallengeDecider``
        in ``classifiers.py`` returns ``True``. This is the case for either a 
        ``401`` response from the client or if the key 
        ``repoze.whoplugins.openid.openidrepoze.whoplugins.openid.openid``
        is present in the WSGI environment.

        The name of this key can be adjusted via the ``openid_field``
        configuration directive.

        The latter is the case when we are coming from the login page
        where the user entered the openid to use.

        ``401`` can come back in any case and then we simply redirect
        to the login form which is configured in the who configuration
        as ``login_form_url``.

        TODO: make the environment key to check also configurable in
        the challenge_decider.

        For the OpenID flow check `the OpenID library documentation
        <http://openidenabled.com/files/python-openid/docs/2.2.1/openid.consumer.consumer-module.html>`_

        """

        request = Request(environ)
        
        # check for the field present, if not redirect to login_form
        if not request.params.has_key(self.openid_field):
            # redirect to login_form
            res = Response()
            res.status = 302
            res.location = self.login_form_url+"?%s=%s" %(self.came_from_field, request.url)
            return res

        # now we have an openid from the user in the request 
        openid_url = request.params[self.openid_field]
        self.log.debug('starting openid request for : %s ' %openid_url)       

        try:
        # we create a new Consumer and start the discovery process for the URL given
        # in the library openid_request is called auth_req btw.
            openid_request = self.get_consumer(environ).begin(openid_url)
        except consumer.DiscoveryFailure, exc:
            # eventually no openid server could be found
            environ[self.error_field] = 'Error in discovery: %s' %exc[0]
            self.log.info('Error in discovery: %s ' %exc[0])     
            return self._redirect_to_loginform(environ)
        except KeyError, exc:
            # TODO: when does that happen, why does plone.openid use "pass" here?
            environ[self.error_field] = 'Error in discovery: %s' %exc[0]
            self.log.info('Error in discovery: %s ' %exc[0])
            return self._redirect_to_loginform(environ)
            return None
        # not sure this can still happen but we are making sure.
        # should actually been handled by the DiscoveryFailure exception above
        if openid_request is None:
            environ[self.error_field] = 'No OpenID services found for %s' %openid_url
            self.log.info('No OpenID services found for: %s ' %openid_url)
            return self._redirect_to_loginform(environ)
       
        # we have to tell the openid provider where to send the user
        # after login so we need to compute this from our path and
        # application URL we simply use the URL we are at right now
        # (which is the form) this will be captured by the repoze.who
        # identification plugin later on it will check if some valid
        # openid response is coming back trust_root is the URL (realm)
        # which will be presented to the user in the login process and
        # should be your applications url TODO: make this
        # configurable?  return_to is the actual URL to be used for
        # returning to this app
        return_to = request.path_url # we return to this URL here
        trust_root = request.application_url
        self.log.debug('setting return_to URL to : %s ' %return_to)
        
        # TODO: usually you should check
        # openid_request.shouldSendRedirect() but this might say you
        # have to use a form redirect and I don't get why so we do the
        # same as plone.openid and ignore it.
        
        # Request additional information (optional here, could require
        # fields as well)...
        if self.sreg_optional or self.sreg_required:
            openid_request.addExtension(
                sreg.SRegRequest(
                    required = self.sreg_required,
                    optional = self.sreg_optional,
                    )
                )

        # TODO: we might also want to give the application some way of adding
        # extensions to this message.
        redirect_url = openid_request.redirectURL(trust_root, return_to) 
        # # , immediate=False)
        res = Response()
        res.status = 302
        res.location = redirect_url
        self.log.debug('redirecting to : %s ' %redirect_url)

        # now it's redirecting and might come back via the identify() method
        # from the openid provider once the user logged in there.
        return res
        
    def _redirect_to_loginform(self, environ={}):
        """redirect the user to the login form"""
        res = Response()
        res.status = 302
        q=''
        ef = environ.get(self.error_field, None)
        if ef is not None:
                q='?%s=%s' %(self.error_field, ef)
        res.location = self.login_form_url+q
        return res
        
                
    # IAuthenticator
    def authenticate(self, environ, identity):
        """Dummy authenticator
        
        This takes the openid found and uses it as the
        userid. Normally you would want to take the openid and search
        a user for it to map maybe multiple openids to a user.  This
        means for you to simply implement something similar to this.
        
        """
        if identity.has_key("repoze.who.plugins.openid.userid"):
                self.log.info('authenticated : %s ',
                              identity['repoze.who.plugins.openid.userid'])
                return identity.get('repoze.who.plugins.openid.userid')


    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, id(self))

