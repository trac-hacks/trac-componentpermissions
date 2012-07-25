import re

from trac.core import *
from trac.config import BoolOption, ListOption, Option
from trac.notification import NotifyEmail
from trac.perm import IPermissionRequestor, IPermissionPolicy
from trac.ticket import model
from trac.resource import ResourceNotFound
from trac.util import as_bool

class ComponentPermissionsPolicy(Component):
    """
    This component provides permissions based on ticket components for Trac.
    """

    implements(IPermissionRequestor, IPermissionPolicy)

    ticket_field_name = Option('component-permissions', 'ticket_field_name', 'component_permissions_field',
        """The name of the field which should be checked to see if the component permission is required.""")

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

    always_private_components = ListOption('component-permissions', 'always_private_components', None,
        doc = """List of components where the component permission check is always required.
              Multiple components should be seperated with comas.""")

    def __init__(self):
        self.account_manager = None
        try:
            from acct_mgr.api import AccountManager
            self.account_manager = AccountManager(self.env)
        except ImportError:
            pass

    # IPermissionRequestor methods
    
    def _get_permission_name(self, component):
        name = re.sub('[^a-zA-Z]+', '_', component).strip('_').upper()
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
        if self.allow_cc:
            cc_list = [user for user in NotifyEmail.addrsep_re.split(ticket['cc']) if user]
            if username in cc_list:
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

    def _get_should_check_permissions(self, ticket):
        # checkbox for ticket is checked
        if as_bool(ticket.values.get(self.ticket_field_name, 0)):
            return True
        # or component is on the list of always private components
        if 'component' in ticket.values:
            if ticket['component'] in self.always_private_components:
                return True
        return False

    def get_permission_actions(self):
        """Return a list of actions defined by this component."""

        yield 'COMPONENT_VIEW'

        for component in model.Component.select(self.env):
            permission = self._get_permission_name(component.name)
            if permission:
                yield permission

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
                should_check_permissions = self._get_should_check_permissions(ticket)
                if should_check_permissions: 
                    if 'component' in ticket.values:
                        component_permission = self._get_permission_name(ticket['component'])
                    bypass = self._get_bypass(ticket, username)
            except ResourceNotFound:
                should_check_permissions = 1 # Fail safe to prevent a race condition

            if should_check_permissions:
                if component_permission not in perm and 'COMPONENT_VIEW' not in perm and not bypass:
                    return False
