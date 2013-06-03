from __future__ import unicode_literals

import base64


class TestCaseUtils(object):
    def get_basic_auth_header(self, user, password):
        """
        Return a dict containg the correct headers to set to make HTTP Basic Auth request
        """
        user_pass = '{0}:{1}'.format(user, password)
        auth_string = base64.b64encode(user_pass.encode('utf-8'))
        auth_headers = {
            'HTTP_AUTHORIZATION': 'Basic ' + auth_string.decode("utf-8"),
        }

        return auth_headers
