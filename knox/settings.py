from datetime import timedelta

from django.conf import settings

USER_SETTINGS = getattr(settings, 'REST_KNOX', {})
ISO_8601 = 'iso-8601'


knox_settings = {
    'SECURE_HASH_ALGORITHM': '',
    'AUTH_TOKEN_CHARACTER_LENGTH': 64,
    'TOKEN_TTL': timedelta(hours=10),
    'USER_SERIALIZER': None,
    'TOKEN_LIMIT_PER_USER': None,
    'AUTO_REFRESH': False,
    'MIN_REFRESH_INTERVAL': 60,
    'AUTH_HEADER_PREFIX': 'Token',
    'EXPIRY_DATETIME_FORMAT': ISO_8601
}

knox_settings.update(USER_SETTINGS)


class CONSTANTS:
    '''
    Constants cannot be changed at runtime
    '''
    TOKEN_KEY_LENGTH = 8
    DIGEST_LENGTH = 128

    def __setattr__(self, *args, **kwargs):
        raise Exception('''
            Constant values must NEVER be changed at runtime, as they are
            integral to the structure of database tables
            ''')


CONSTANTS = CONSTANTS()
