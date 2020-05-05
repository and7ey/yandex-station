'''Model classes and utility functions
'''
import logging
import datetime
import json

from google.appengine.ext import ndb
from google.appengine.api import memcache


class User(ndb.Model):
    '''

    Index
      Key:              email
    '''
    yandex_token = ndb.StringProperty(required=False, indexed=False)
    device_token = ndb.StringProperty(required=False, indexed=False)
    device_address = ndb.StringProperty(required=False, indexed=False)
    scenario1 = ndb.TextProperty(required=False, indexed=False)
    scenario2 = ndb.TextProperty(required=False, indexed=False)
    # email = ndb.StringProperty()


def add_user(email, yandex_token=None, device_token=None, device_address=None, scenario1=None, scenario2=None):
    logging.debug('Adding/updating user %s...' % email)
    record = User.get_by_id(email)
    if not record: # add new record
        record = User(id=email)
    if yandex_token: record.yandex_token = yandex_token
    if device_token: record.device_token = device_token
    if device_address: record.device_address = device_address
    if scenario1 and scenario1[0]: record.scenario1 = json.dumps(scenario1)
    if scenario2 and scenario2[0]: record.scenario2 = json.dumps(scenario2)
    try:
        record.put()
        return True
    except Exception, error_message:
        logging.exception('Failed to add/update user, exception happened - %s' % error_message)
    return False

def get_user(email):
    logging.debug('Getting user %s...' % str(email))
    record = User.get_by_id(email)
    logging.info('User is %s' % str(record))
    return record