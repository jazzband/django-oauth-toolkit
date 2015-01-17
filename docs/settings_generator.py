"""
Custom Sphinx documentation module to generate the table of all settings.
"""


DESCRIPTIONS = {
    'ACCESS_TOKEN_EXPIRE_SECONDS': """
The number of seconds an access token remains valid. Requesting a protected
resource after this duration will fail. Keep this value high enough so clients
can cache the token for a reasonable amount of time.
""",
    'APPLICATION_MODEL': """
The import string of the class (model) representing your applications. Overwrite
this value if you wrote your own implementation (subclass of
``oauth2_provider.models.Application``).
""",
    'AUTHORIZATION_CODE_EXPIRE_SECONDS': """
The number of seconds an authorization code remains valid. Requesting an access
token after this duration will fail. :rfc:`4.1.2` recommends a
10 minutes (600 seconds) duration.
""",
    'CLIENT_ID_GENERATOR_CLASS': """
The import string of the class responsible for generating client identifiers.
These are usually random strings.
""",
    'CLIENT_SECRET_GENERATOR_CLASS': """
The import string of the class responsible for generating client secrets.
These are usually random strings.
""",
    'CLIENT_SECRET_GENERATOR_LENGTH': """
The length of the generated secrets, in characters. If this value is too low,
secrets may become subject to bruteforce guessing.
""",
    'OAUTH2_VALIDATOR_CLASS': """
The import string of the ``oauthlib.oauth2.RequestValidator`` subclass that
validates every step of the OAuth2 process.
""",
    'READ_SCOPE': """
The name of the *read* scope.
""",
    'REQUEST_APPROVAL_PROMPT': """
Can be ``'force'`` or ``'auto'``.
The strategy used to display the authorization form. Refer to :ref:`skip-auth-form`.
""",
    'SCOPES': """
A dictionnary mapping each scope name to its human description.
""",
    'WRITE_SCOPE': """
The name of the *write* scope.
""",
}


from docutils import nodes
from docutils.parsers.rst import Directive, directives
from docutils.utils import SystemMessagePropagation


def _type_choice(argument):
    return directives.choice(argument, ('table', 'definitions'))


class SettingsGenerator(Directive):
    """Generate the settings table/definition list."""

    required_arguments = 0
    optional_arguments = 0
    final_argument_whitespace = True
    option_spec = {'type': _type_choice}
    has_content = True
    node_class = None

    _headers = ("Name", "Can be empty", "Description")
    _headers_size = (1, 1, 6)

    def _build_definition_list(self, defaults):
        from oauth2_provider import settings

        items = []
        for setting, default_value in defaults:
            text_nodes, messages = self.state.inline_text(DESCRIPTIONS.get(setting, "TODO").strip(), self.lineno)
            node_name = nodes.literal(text=setting)
            node_default = nodes.paragraph(text="Default value: ")
            node_default += nodes.literal(text=repr(default_value))
            node_description = nodes.paragraph()
            node_description.extend(text_nodes)
            subitems = [node_default, node_description]

            if setting in settings.MANDATORY:
                notice = nodes.paragraph()
                notice += nodes.strong(text="The value cannot be empty.")
                subitems.append(notice)

            term = nodes.term()
            term += node_name
            items.append(nodes.definition_list_item('', term, nodes.definition('', *subitems)))

        deflist = nodes.definition_list('', *items)
        return [deflist]

    def _build_table(self, defaults):
        from oauth2_provider import settings

        table = nodes.table()
        tgroup = nodes.tgroup(cols=len(self._headers))
        table += tgroup
        for factor in self._headers_size:
            colspec = nodes.colspec(colwidth=factor)
            tgroup += colspec

        tbody = nodes.tbody()
        for setting, default_value in defaults:
            text_nodes, messages = self.state.inline_text(DESCRIPTIONS.get(setting, "TODO").strip(), self.lineno)
            node_name = nodes.paragraph()
            node_name += nodes.literal(text=setting)
            node_default = nodes.paragraph(text="Default value: ")
            node_default += nodes.literal(text=repr(default_value))
            node_empty = nodes.paragraph(text="No" if setting in settings.MANDATORY else "Yes")
            node_description = nodes.paragraph()
            node_description.extend(text_nodes)
            cells = [[node_name, node_default], [node_empty], [node_description]]
            row_node = nodes.row()
            for cell in cells:
                row_node += nodes.entry('', *cell)
            tbody += row_node

        thead = nodes.thead()
        thead_row = nodes.row()
        for head in self._headers:
            entry = nodes.entry(head, nodes.paragraph(text=head))
            thead_row += entry
        thead += thead_row
        tgroup += thead
        tgroup += tbody
        return [table]

    def run(self):
        from oauth2_provider import settings
        defaults = sorted([(k, v) for k, v in settings.DEFAULTS.items() if not k.startswith('_')])

        opt_type = self.options.get('type')
        if opt_type == 'table':
            return self._build_table(defaults)
        elif opt_type == 'definitions':
            return self._build_definition_list(defaults)
        else:
            error = self.state_machine.reporter.error("type must be 'table' or 'definitions'")
            raise SystemMessagePropagation(error)


def setup(app):
    """
    Install the plugin.

    :param app: Sphinx application context.
    """
    app.add_directive('settings_generator', SettingsGenerator)
    return
