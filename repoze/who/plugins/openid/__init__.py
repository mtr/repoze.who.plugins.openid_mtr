from identification import OpenIdIdentificationPlugin
from repoze.who.utils import resolveDotted

def make_identification_plugin(
    store='mem',
    openid_field="openid",
    db_connection_factory=None,
    session_name=None,
    login_handler_path=None,
    logout_handler_path=None,
    login_form_url=None,
    error_field='error',
    logged_in_url=None,
    logged_out_url=None,
    came_from_field='came_from',
    store_file_path='',
    rememberer_name=None,
    sql_associations_table='',
    sql_nonces_table='',
    sql_connstring='',
    md_provider_name='openid_md',
    sreg_required='',
    sreg_optional='',
    ):
    if store not in (u'mem',u'file',u'sql'):
        raise ValueError("store needs to be 'mem', 'sql' or 'file'")
    if login_form_url is None:
        raise ValueError("login_form_url needs to be given")
    if rememberer_name is None:
        raise ValueError("rememberer_name needs to be given")
    if login_handler_path is None:
        raise ValueError("login_handler_path needs to be given")
    if logout_handler_path is None:
        raise ValueError("logout_handler_path needs to be given")
    if session_name is None:
        raise ValueError("session_name needs to be given")
    if logged_in_url is None:
        raise ValueError("logged_in_url needs to be given")
    if logged_out_url is None:
        raise ValueError("logged_out_url needs to be given")
    
    sreg_required = [attr.strip(',') for attr in sreg_required.split()] or None
    sreg_optional = [attr.strip(',') for attr in sreg_optional.split()] or None
    
    plugin = OpenIdIdentificationPlugin(
        store, 
        openid_field=openid_field,
        error_field=error_field,
        db_connection_factory=resolveDotted(db_connection_factory),
        session_name=session_name,
        login_form_url=login_form_url,
        login_handler_path=login_handler_path,
        logout_handler_path=logout_handler_path,
        store_file_path=store_file_path,
        logged_in_url=logged_in_url,
        logged_out_url=logged_out_url,
        came_from_field=came_from_field,
        rememberer_name=rememberer_name,
        sql_associations_table=sql_associations_table,
        sql_nonces_table=sql_nonces_table,
        sql_connstring=sql_connstring,
        md_provider_name=md_provider_name,
        sreg_required=sreg_required,
        sreg_optional=sreg_optional,
#        cookie_identifier=cookie_identifier,
#        cookie_secret=cookie_secret,                                
        )
    return plugin

