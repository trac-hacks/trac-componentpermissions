import re

from trac.core import *
from trac.config import BoolOption, Option
from trac.notification import NotifyEmail
from trac.perm import IPermissionRequestor, IPermissionPolicy
from trac.ticket import model
from trac.resource import ResourceNotFound
from trac.util import as_bool
from trac.web import IRequestFilter

class ComponentPermissionsPolicy(Component):
    """
    This component provides permissions based on ticket components for Trac.
    """

    implements(IPermissionRequestor, IPermissionPolicy, IRequestFilter)

    ticket_field_name = Option('component-permissions', 'ticket_field_name', '',
        """The name of the field which should be checked to see if the component permission is required.
        If not defined or empty, component permission is always required.""")

    allow_reporter = BoolOption('component-permissions', 'allow_reporter', 'false',
        """"Whether the reporter of a ticket should have access to that ticket even if
        they do not have COMPONENT_VIEW or COMPONENT_*_VIEW privileges.""")

    allow_cc = BoolOption('component-permissions', 'allow_cc', 'false',
        """Whether users listed in the cc field of a ticket should have access to that ticket even
        if they do not have COMPONENT_VIEW or COMPONENT_*_VIEW privileges.""")

    allow_owner = BoolOption('component-permissions', 'allow_owner', 'false',
        """Whether the owner of a ticket should have access to that ticket even if
        they do not have COMPONENT_VIEW or COMPONENT_*_VIEW privileges.""")

    allow_cc_email = BoolOption('component-permissions', 'allow_cc_email', 'false',
        """Whether users with their e-mail listed in the cc field of a ticket should have access to
        that ticket even if they do not have COMPONENT_VIEW or COMPONENT_*_VIEW privileges. Make sure
        e-mail is verified and cannot be freely changed.""")

    hide_components = BoolOption('component-permissions', 'hide_components', 'false',
        """Whether components the user does not have permissions for should be hidden.""")

    def __init__(self):
        self.account_manager = None
        try:
            from acct_mgr.api import AccountManager
            self.account_manager = AccountManager(self.env)
        except ImportError:
            pass

    # IPermissionRequestor methods
    
    def _get_permission_name(self, component):
        name = re.sub('[^a-zA-Z0-9]+', '_', component).strip('_').upper()
        if name:
            return 'COMPONENT_%s_VIEW' % (name,)
        else:
            return None

    def _get_email(self, username):
        cnx = self.env.get_db_cnx()
        cursor = cnx.cursor()
        cursor.execute("""SELECT DISTINCT e.value FROM session AS s LEFT JOIN session_attribute AS e
                          ON (e.sid=s.sid AND e.authenticated=1 AND e.name = 'email')
                          WHERE s.authenticated=1 AND s.sid=%s""", (username,))
        for email, in cursor:
            return email
        return None

    def _get_bypass(self, ticket, username):
        if not username or username == 'anonymous':
            return False
        if self.allow_owner and ticket['owner'] == username:
            return True
        if self.allow_reporter and ticket['reporter'] == username:
            return True

        if not self.allow_cc and not self.allow_cc_email:
            return False

        cc_list = [user for user in NotifyEmail.addrsep_re.split(ticket['cc']) if user]

        if self.allow_cc and username in cc_list:
            return True

        if self.allow_cc_email:
            email = self._get_email(username)
            if email and email in cc_list:
                if self.account_manager:
                    if self.account_manager.email_verified(username, email):
                        return True
                else:
                    return True

        return False

    def get_permission_actions(self):
        """Return a list of actions defined by this component."""

        permissions = ['COMPONENT_VIEW']

        for component in model.Component.select(self.env):
            permission = self._get_permission_name(component.name)
            if permission:
                permissions.append(permission)

        return permissions

    # IPermissionPolicy methods

    def check_permission(self, action, username, resource, perm):
        """Check that the action can be performed by username on the resource."""

        # To prevent recursion
        if action in self.get_permission_actions():
            return
        # To prevent recursion when used together with sensitive tickets
        if action == 'SENSITIVE_VIEW':
            return

        # Check whether we're dealing with a ticket resource
        while resource:
            if resource.realm == 'ticket':
                break
            resource = resource.parent
        
        if resource and resource.realm == 'ticket' and resource.id is not None:
            component_permission = 'COMPONENT_VIEW' # Default just to make check logic simpler
            bypass = False
            try:
                ticket = model.Ticket(self.env, int(resource.id))
                should_check_permissions = not self.ticket_field_name or ticket.values.get(self.ticket_field_name, 0)
                if as_bool(should_check_permissions):
                    if 'component' in ticket.values and ticket['component'] and self._get_permission_name(ticket['component']) in self.get_permission_actions():
                        component_permission = self._get_permission_name(ticket['component'])
                    bypass = self._get_bypass(ticket, username)
            except ResourceNotFound:
                should_check_permissions = 1 # Fail safe to prevent a race condition

            if as_bool(should_check_permissions):
                if component_permission not in perm and 'COMPONENT_VIEW' not in perm and not bypass:
                    return False

    # IRequestFilter methods

    def pre_process_request(self, req, handler):
        return handler

    def post_process_request(self, req, template, data, content_type):
        if self.hide_components and not self.ticket_field_name and 'COMPONENT_VIEW' not in req.perm and template in ['ticket_box.html', 'ticket.html', 'ticket_preview.html', 'query.html']:
            objects = []
            if data.get('fields', None):
                objects.append(data['fields'].values() if hasattr(data['fields'], 'values') else data['fields'])
            if req.chrome.get('script_data', None) and req.chrome['script_data'].get('properties', None):
                properties = []
                for name, prop in req.chrome['script_data']['properties'].items():
                    prop['name'] = name
                    properties.append(prop)
                objects.append(properties)
            for obj in objects:
                for field in obj:
                    if field['name'] == 'component':
                        field['options'] = [component for component in field['options'] if self._get_permission_name(component) in req.perm]
                        break
            query = data.get('query', None)
            if query and query.group == 'component' and 'groups' in data:
                groups = []
                for (component, tickets) in data['groups']:
                    if self._get_permission_name(component) in req.perm:
                        groups.append((component, tickets))
                data['groups'] = groups
        return (template, data, content_type)
