import os
basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'fantc0000000987234'
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    SQLALCHEMY_RECORD_QUERIES = True

    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') or 'xxxxxxxxx'
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or 'yyyyyyyyy'
    TOPIK_MAIL_SUBJECT_PREFIX = '[TOPIK]'
    TOPIK_MAIL_SENDER = 'TOPIK Admin <TOPIK@example.com>'
    TOPIK_ADMIN = os.environ.get('TOPIK_ADMIN') or 'xxxxxxxxx@gmail.com'
    TOPIK_POSTS_PER_PAGE = 20
    TOPIK_FOLLOWERS_PER_PAGE = 50
    TOPIK_COMMENTS_PER_PAGE = 30

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
#    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
#        'sqlite:///' + os.path.join(basedir, 'data-dev.sqlite')
    USER = 'root'
    PASSWORD = 'root123'
    HOST = 'localhost'
    DB = 'test'
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://'+USER+':'+PASSWORD+'@'+HOST+'/'+DB

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'data-test.sqlite')


class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'data.sqlite')


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,

    'default': DevelopmentConfig
}
