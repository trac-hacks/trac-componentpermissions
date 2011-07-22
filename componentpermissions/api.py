import re

from trac.core import *
from trac.config import Option
from trac.perm import IPermissionRequestor, IPermissionPolicy
from trac.ticket import model
from trac.resource import ResourceNotFound

class ComponentPermissionsPolicy(Component):
    """
    This component provides permissions based on ticket components for Trac.
    """

    implements(IPermissionRequestor, IPermissionPolicy)

    ticket_field_name = Option('component-permissions', 'ticket_field_name', 'component_permissions_field',
        """The name of the field which should be checked to see if the component permission is required.""")

    # IPermissionRequestor methods
    
    def _get_permission_name(self, component):
        name = re.sub('[^a-zA-Z]+', '_', component).strip('_').upper()
        if name:
            return 'COMPONENT_%s_VIEW' % (name,)
        else:
            return None

    def get_permission_actions(self):
        for component in model.Component.select(self.env):
            permission = self._get_permission_name(component.name)
            if permission:
                yield permission

    # IPermissionPolicy methods

    def check_permission(self, action, username, resource, perm):
        # To prevent recursion
        if action in self.get_permission_actions():
            return

        # Check whether we're dealing with a ticket resource
        while resource:
            if resource.realm == 'ticket':
                break
            resource = resource.parent
        
        if resource and resource.realm == 'ticket' and resource.id is not None:
            try:
                ticket = model.Ticket(self.env, int(resource.id))
                should_check_permissions = ticket.values.get(self.ticket_field_name, 0)
            except ResourceNotFound:
                # There is a short race condition here but we cannot do much
                return

            if should_check_permissions and int(should_check_permissions) and 'component' in ticket.values:
                permission = self._get_permission_name(ticket['component'])
                if permission and permission not in perm and 'TICKET_ADMIN' not in perm:
                    return False
