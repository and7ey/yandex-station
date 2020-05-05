# coding: utf-8
from __future__ import unicode_literals

import json
import logging
import random
import hashlib
import re
import datetime
import os
import time

from google.appengine.api import users
from google.appengine.api import urlfetch
from google.appengine.api import taskqueue
# import urllib

import websocket
import ssl

import models

#import vk

from flask import Flask, render_template, request
app = Flask(__name__)

logging.basicConfig(level=logging.DEBUG)

@app.route("/device-token", methods=['GET'])
def deviceToken():
    device_id = None

    yandex_token = request.args.get('Yandex-Token')
    if yandex_token:
        try:
            response = urlfetch.Fetch(
                url='https://quasar.yandex.net/glagol/device_list',
                method=urlfetch.GET,
                headers={
                    'Authorization': 'oauth %s' % yandex_token
                },
                deadline=60)
        except Exception, error_message:
            logging.exception('Failed to access Quasar URL, exception happened - %s' % error_message)
            return 'Failed to access Quasar URL'
        if response:
            if response.status_code == 200:
                if response and response.content:
                    logging.info(response.content)
                    response_json = json.loads(response.content)
                    if response_json:
                        if response_json.get('status') == 'ok':
                            if response_json.get('devices') and len(response_json.get('devices')) > 0:
                                device_id = None
                                for dd in response_json.get('devices'):
                                    if dd.get('platform') == 'yandexstation' or dd.get('platform') == 'yandexmodule':
                                        device_id = dd.get('id')
                                        break
                                if not device_id:
                                    return 'No Yandex Station found'
                            else:
                                return 'No devices'
                        else:
                            return response.content
                    else:
                        return 'Failed to parse JSON'
                else:
                    return 'No response received from Quasar'
            else:
                return 'Error ' + str(response.status_code)
    else:
        return 'No Yandex Token given'

    logging.info(str(device_id))

    if device_id:
        response = None
        response_json = None
        try:
            response = urlfetch.Fetch(
                url='https://quasar.yandex.net/glagol/token?device_id=%s&platform=yandexstation' % device_id,
                method=urlfetch.GET,
                headers={
                    'Authorization': 'oauth %s' % yandex_token
                },
                deadline=60)
        except Exception, error_message:
            logging.exception('Failed to get device token, exception happened - %s' % error_message)
            return 'Failed to get device token'
        if response:
            if response.status_code == 200:
                if response and response.content:
                    logging.info(response.content)
                    response_json = json.loads(response.content)
                    if response_json:
                        if response_json.get('status') == 'ok':
                            if response_json.get('token'):
                                return response_json.get('token')
                            else:
                                return 'No device token found'
                        else:
                            return response.content
                    else:
                        return 'Failed to parse JSON'
                else:
                    return 'No response received from Quasar'
            else:
                return 'Error ' + str(response.status_code)

    else:
        return 'Failed to get device id'


def send_text(device_address, device_token, texts):
    device_address = 'wss://%s' % device_address.encode('utf-8')
    logging.info(device_address)
    logging.info(device_token)
    ws = websocket.WebSocket(sslopt={'cert_reqs': ssl.CERT_NONE}, origin='http://yandex.ru/')

    #texts.insert(0, '.^0') # alisa bug fixed, we don't need it more

    for t in texts:

        if t.strip() != '':
            if '^' in t:
                text = t.split('^')[0]
                pause = int(t.split('^')[1])
            else:
                text = t
                pause = 3
            logging.info(text)
            logging.info(str(pause))

            try:
                ws.connect(str(device_address))
                ws.send(json.dumps({
                    'conversationToken': device_token,
                    'payload': {'command':'sendText', 'text': text}
                }))
            except Exception, error_message: # try again, if it is failed
                logging.info('Exception happened: %s' % error_message)
                ws.connect(str(device_address))
                ws.send(json.dumps({
                    'conversationToken': device_token,
                    'payload': {'command':'sendText', 'text': text}
                }))

            if text != texts[-1]: # don't wait, if this is last command

                # ws.send(json.dumps({
                #  'conversationToken': device_token,
                #  'payload': {
                #     'command': 'serverAction',
                #     'serverActionEventPayload': {
                #         'type': 'server_action',
                #         'name': 'on_get_greetings',
                #         'payload': {}
                #     }
                #  }
                # }))
                #result =  ws.recv()
                #logging.info(result)

                time.sleep(pause)
                    # this approach doesn't work well
                    # while True:
                    #     alice_state = None
                    #     result = None
                    #     time.sleep(1)
                    #     try:
                    #         result =  ws.recv()
                    #     except websocket.WebSocketConnectionClosedException:
                    #         ws.connect(str(device_address))
                    #         result =  ws.recv()

                    #     logging.info(str(result))
                    #     if result:
                    #         try:
                    #             result_json = json.loads(result)
                    #             if result_json and result_json.get('state') and result_json.get('state').get('aliceState'):
                    #                 alice_state = result_json.get('state').get('aliceState')
                    #                 logging.info(alice_state)
                    #                 # status is present only in some error messages
                    #                 if alice_state in ['IDLE', 'LISTENING'] and not (result_json.get('status')): # SPEAKING, UNKNOWN, 'BUSY'
                    #                     break
                    #         except Exception:
                #             pass
    # ws.close() # doesn't close properly, so just don't do it


@app.route("/test-connection", methods=['GET'])
def testConnection():
    device_token = request.args.get('Device-Token')
    device_address = request.args.get('Device-Address')

    if device_token and device_address:
        device_address = device_address.replace('http://','').replace('https://','').replace('wss://','')
        if not ':' in device_address:
            device_address += ':1961'

        # userinfo = models.UserInfo(
        #     id = user.user_id(),
        #     nickname = user.nickname(),
        #     email = user.email()
        # )
        # userinfo.put()
        send_text(device_address, device_token, ['Повтори за мной Привет от навыка Мои сценарии! Все настроено верно!'])


        return 'ok'

    else:
        return 'No device token or/and address are given'



@app.route("/", methods=['GET'])
def index_get():
    user = users.get_current_user()
    if user:
        yandex_token = ''
        device_token = ''
        device_address = ''
        case1step1 = ''
        case1step2 = ''
        case1step3 = ''
        case2step1 = ''
        case2step2 = ''
        case2step3 = ''
        userdb = models.get_user(user.email())
        if userdb:
            yandex_token = userdb.yandex_token
            device_token = userdb.device_token
            device_address = userdb.device_address
            if userdb.scenario1:
                scenario1 = json.loads(userdb.scenario1)
                case1step1 = scenario1[0]
                if len(scenario1)>0: case1step2 = scenario1[1]
                if len(scenario1)>1: case1step3 = scenario1[2]
            if userdb.scenario2:
                scenario2 = json.loads(userdb.scenario2)
                case2step1 = scenario2[0]
                if len(scenario2)>0: case2step2 = scenario2[1]
                if len(scenario2)>1: case2step3 = scenario2[2]


        return render_template('user.html',
            url = users.create_logout_url("/"),
            user = user.email(),
            yandex_token = yandex_token,
            device_token = device_token,
            device_address = device_address,
            case1step1 = case1step1,
            case1step2 = case1step2,
            case1step3 = case1step3,
            case2step1 = case2step1,
            case2step2 = case2step2,
            case2step3 = case2step3
            )
    else:
        return render_template('index.html', url=users.create_login_url("/"))


@app.route("/", methods=['POST'])
def index_post():
    user = users.get_current_user()
    if user:
        yandex_token = request.form['yandex_token']
        device_token = request.form['device_token']
        device_address = request.form['device_address']
        device_address = device_address.replace('http://','').replace('https://','').replace('wss://','')
        if not ':' in device_address:
            device_address += ':1961'

        case1step1 = request.form['case1step1']
        case1step2 = request.form['case1step2']
        case1step3 = request.form['case1step3']

        case2step1 = request.form['case2step1']
        case2step2 = request.form['case2step2']
        case2step3 = request.form['case2step3']

        models.add_user(user.email(),
            yandex_token,
            device_token,
            device_address,
            [case1step1, case1step2, case1step3],
            [case2step1, case2step2, case2step3]
            )

        return '<html><body>Data successfully saved</body></html>'
    else:
        return ''



@app.route("/policy", methods=['GET'])
def policy():
    return render_template('policy.html')















@app.route("/alice/", methods=['POST'])

def main():
    logging.info('Request: %r', request.json)
    logging.info('Request headers: %r', request.headers)

    response = {
        "version": request.json['version'],
        "session": request.json['session'],
        "response": {
            "end_session": False
        }
    }

    handle_dialog(request, response)

    logging.info('Response: %r', response)

    return json.dumps(
        response,
        ensure_ascii=False,
        indent=2
    )


def request_auth(req, res):
    # https://yandex.ru/dev/dialogs/alice/doc/auth/account-linking-in-custom-skills-docpage/
    # https://developers.google.com/identity/protocols/OAuth2InstalledApp
    if req['meta']['interfaces']['account_linking'] == {}:
        res['start_account_linking'] = {}
        del res['response'] # don't work together with registration request
    else:
        res['response']['text'] = 'Для моей работы необходима связка аккаунтов, но она не работает на этой поверхности. Осуществи ее на другом устройстве и возвращайся. Связка аккаунтов работает в приложениях Яндекса на iOS и Android, на Яндекс.Станции и Яндекс.Модуле, на колонках с Алисой.'
        res['response']['tts'] = 'Для моей работы необходима связка аккаунтов, но она не работает на этой поверхности. Осуществи ее на другом устройстве и возвращайся. Связка аккаунтов работает в приложениях Яндекса на iOS и Android, на Яндекс Станции и Яндекс Модуле, на колонках с Алисой.'



@app.route("/alice/task", methods=['GET'])
def perform_scenario():

    user_email = request.args.get('u')
    case = request.args.get('c')

    if user_email and case:
        logging.info('Performing task for user %s' % user_email)
        user = models.get_user(user_email)
        case = int(case)
        if case==0: # test scenario
            send_text(user.device_address, user.device_token, ['Повтори за мной Супер! Похоже, что всё работает как надо!'])
        elif case==1 or case==2:
            if case==1:
                scenario = user.scenario1
            elif case==2:
                scenario = user.scenario2
            if scenario[0]:
                commands = json.loads(scenario)
                if commands:
                    send_text(user.device_address, user.device_token, commands)
                else:
                    send_text(user.device_address, user.device_token, ['Повтори за мной Не удалось прочитать сценарий.'])
            else:
                send_text(user.device_address, user.device_token, ['Повтори за мной Отсутствуют команды в данном сценарии. Задайте их на сайте.'])
    return ''



def handle_scenarios(request, res, case):
    req = request.json

    if request.headers.get('Authorization'):

        token = request.headers.get('Authorization').replace('Bearer ', '')
        if token:
            user_email = get_user_email(token)
            if user_email:
                user = models.get_user(user_email)
                if user and user.device_address and user.device_token:
                    res['response']['end_session'] = True
                    if case==0: # test scenario
                        res['response']['text'] = 'Надеюсь, ты услышишь мое тайное послание через пару секунд.'
                    else:
                        res['response']['text'] = '.'
                    taskqueue.add(url='/alice/task?u=%s&c=%s' % (user_email, case), countdown=3, method='GET')
                else:
                    res['response']['text'] = 'Похоже, ты не завершил настройки на сайте. Сделай это и возвращайся!'

            else:
                res['response']['text'] = 'Похоже, ты еще не сделал настройки на сайте. Либо использовал разные аккаунты здесь и на сайте. Проверь все и возвращайся.'
        else:
            res['response']['text'] = 'Сначала необходимо пройти авторизацию, скажи "Авторизация" для начала.'

        return
    else:
        request_auth(req, res)


def get_user_email(token):
    response = None
    try:
        response = urlfetch.Fetch(
            url='https://www.googleapis.com/oauth2/v1/userinfo?alt=json',
            method=urlfetch.GET,
            headers={
                'Authorization': 'Bearer %s' % token
            },
            deadline=60)
    except Exception, error_message:
        logging.exception('Failed to access Quasar URL, exception happened - %s' % error_message)

    if response and response.status_code == 200 and response.content:
        response_json = json.loads(response.content)
        if response_json and response_json.get('email'):
            return response_json.get('email')

    return None

def handle_dialog(request, res):
    # https://yandex.ru/dev/dialogs/alice/doc/protocol-docpage/
    # https://cloud.yandex.ru/services/speechkit

    req = request.json

    user_id = req['session']['user_id']

    if req.get('account_linking_complete_event') == {}:
        suggests = [
            {'title': 'Настройки', 'url': 'https://yandex-station.appspot.com', 'hide': True},
            {'title': 'Сценарий 1', 'hide': True},
            {'title': 'Сценарий 2', 'hide': True}
        ]

        token = request.headers.get('Authorization').replace('Bearer ', '')
        user_email = get_user_email(token)
        if user_email:
            models.add_user(user_email)

            res['response']['text'] = 'Отлично! Теперь зайди на сайт https://yandex-station.appspot.com, авторизуйся там под этим же аккаунтом (%s) - и настрой свои сценарии. Обрати внимание! Зайти на сайт через Яндекс.Браузер не получится, используй Chrome или Safari.' % user_email
            res['response']['tts'] = 'Отлично! Теперь зайди на сайт, указанный в описании навыка в каталоге, - и настрой свои сценарии. Обрати внимание! Зайти на сайт через Яндекс Браузер не получится, используй Хром или Сафари.'
            res['response']['buttons'] = suggests
        else:
            res['response']['text'] = 'Что-то пошло не так. Попробуй снова - скажи "Авторизация".'
        return


    request_text = req['request']['command'].lower().replace('?','')


    if request_text == 'ping':
        res['response']['text'] = 'pong'
        return

    # new user
    if req['session']['new'] and request_text=='':

        if not request.headers.get('Authorization'): # new user
            suggests = [
                {'title': 'Авторизация', 'hide': True},
                {'title': 'Сценарий 1', 'hide': True},
                {'title': 'Сценарий 2', 'hide': True}
            ]

            res['response']['buttons'] = suggests
            res['response']['text'] = 'Привет! Я могу помочь создать тебе сложные сценарии. Например, чтоб по одному запросу Алиса рассказывала погоду и затем включала музыку. \n\nСценарии нужно настроить. Скажи "Авторизация", чтобы я запомнила тебя.'
        else:
            suggests = [
                {'title': 'Авторизация', 'hide': True},
                {'title': 'Сценарий 1', 'hide': True},
                {'title': 'Сценарий 2', 'hide': True}
            ]
            res['response']['buttons'] = suggests
            res['response']['text'] = 'Скажи Сценарий 1 или Сценарий 2 для запуска сценариев.'
        return


    if request_text in [
        'авторизация',
        'вход',
        'войти'
    ]:

        if request.headers.get('Authorization'):
            suggests = [
                {'title': 'У кого день рождения сегодня?', 'hide': True},
                {'title': 'У кого день рождения завтра?', 'hide': True}
            ]

            res['response']['text'] = 'Ранее ты уже проходил регистрацию - повторно делать это не требуется. Если на сайте ты уже настроил сценарии, то просто скажи "Сценарий 1".'
            res['response']['buttons'] = suggests
        else:
            request_auth(req, res)
        return


    if 'сценарий 1' in request_text or 'сценарий один' in request_text:
        handle_scenarios(request, res, 1)
        return

    if 'сценарий 2' in request_text or 'сценарий два' in request_text:
        handle_scenarios(request, res, 2)
        return

    if request_text in [
        'настройки',
        'настройка'
    ]:
        suggests = [
            {'title': 'Тест', 'hide': True},
            {'title': 'Сценарий 1', 'hide': True},
            {'title': 'Сценарий 2', 'hide': True}
        ]

        res['response']['text'] = 'Сделаешь настройки - возвращайся! Скажи "Тест", чтобы проверить настройки.'
        res['response']['buttons'] = suggests
        return

    if request_text in [
        'тест',
        'тестирование',
        'проверка'
    ]:

        handle_scenarios(request, res, case=0)
        return


    if request_text in [
        'что ты умеешь',
        'помощь'
    ]:
        suggests = [
            {'title': 'Авторизация', 'hide': True},
            {'title': 'Сценарий 1', 'hide': True},
            {'title': 'Сценарий 2', 'hide': True}
        ]

        res['response']['text'] = 'Я умею создавать сложные сценарии. Например, чтоб по одному запросу Алиса рассказывала погоду и затем включала музыку. \n\nСценарии нужно настраивать на моем сайте. Скажи "Авторизация", чтобы я запомнила тебя.'

        res['response']['buttons'] = suggests
        return


    # unknown command
    else:
        suggests = [
             {'title': 'Авторизация', 'hide': True},
             {'title': 'Сценарий 1', 'hide': True},
             {'title': 'Сценарий 2', 'hide': True}
        ]

        res['response']['text'] = 'Кажется, я тебя неправильно поняла. Корректные команды - "Авторизация", "Сценарий 1", "Сценарий 2".'
        res['response']['buttons'] = suggests
        return