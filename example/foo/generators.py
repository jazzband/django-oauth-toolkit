import random
import string
from oauth2_provider.generators import BaseHashGenerator


class ClientIdGenerator(BaseHashGenerator):
    def hash(self):
        return ''.join(random.choice(string.letters + string.digits) for i in range(100))
