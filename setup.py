from setuptools import setup

VERSION = '0.1.7'
PACKAGE = 'componentpermissions'

setup(
	name = 'ComponentPermissionsPlugin',
	version = VERSION,
	description = "Provides permissions based on ticket components for Trac.",
	author = 'Mitar',
	author_email = 'mitar.trac@tnode.com',
	url = 'http://mitar.tnode.com/',
	keywords = 'trac plugin',
	license = "AGPLv3",
	packages = [PACKAGE],
    include_package_data = True,
	install_requires = [],
	zip_safe = False,
	entry_points = {
		'trac.plugins': '%s = %s' % (PACKAGE, PACKAGE),
	},
)
