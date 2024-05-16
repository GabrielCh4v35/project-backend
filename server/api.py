from flask import Flask, jsonify, request
from flask_cors import CORS
from database import *
import bcrypt
import jwt
from jwt import InvalidSignatureError
import datetime
from datetime import timezone


secret_key = 'e6b8e25c0e90427bbf52b9adfd007c0979fa59387d2de55d486d32550a815e6c'

class ServerApi:

    def __init__(self, host='127.0.0.1', port=8080):
        self.host = host
        self.port = port
        self.app = Flask(__name__)
        CORS(self.app)  # Permitindo solicitações de qualquer origem
        self.connector = MySQLConnector()
        self.connector.connect()

        @self.app.route('/')
        def index():
            return 'Sucesso'

        # USERS ==========================================================================================================================

        @self.app.route('/create_user', methods=['POST'])
        def create_user():

            # Obtendo os dados enviados como JSON
            data = request.json
            complete_name = data.get('complete_name')
            email = data.get('email')
            password_hash = data.get('password')
            password_hash = self.encrypt_password(password_hash)
            
            # Gerando Tokens JWT
            access_token = jwt.encode({'email': email, 'exp': datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(hours=1)}, secret_key)


            try:
                # Inserindo os dados na tabela USERS
                cursor = self.connector.connection.cursor()
                query = ("INSERT INTO USERS (COMPLETE_NAME, EMAIL, PASSWORD_HASH, ACCESS_TOKEN) "
                        "VALUES (%s, %s, %s, %s)")
                data = (complete_name, email, password_hash, access_token)
                cursor.execute(query, data)
                self.connector.connection.commit()
                cursor.close()
                
                return 'success'
            except Exception  as err:
                return f'Erro ao criar usuário: {err}'

        @self.app.route('/login', methods=['POST'])
        def login():

            # Obtendo os dados enviados como JSON
            data = request.json
            email = data.get('email')
            password = data.get('password')

            try:
                # Obtendo os dados do usuário do banco de dados
                cursor = self.connector.connection.cursor()
                query = ("SELECT EMAIL, PASSWORD_HASH, ACCESS_TOKEN FROM USERS WHERE EMAIL = %s")
                cursor.execute(query, (email,))
                user = cursor.fetchone()

                if user:
                    # Obtendo a senha criptografada armazenada no banco de dados
                    senha_criptografada_armazenada = user[1]
                    
                    # Verificando se a senha fornecida corresponde à senha criptografada armazenada
                    if bcrypt.checkpw(password.encode('utf-8'), senha_criptografada_armazenada.encode('utf-8')):
                        access_token = user[2]

                        # Verificando a assinatura do token
                        try:
                            cursor.close()
                            return jsonify({'access_token': access_token.encode('utf-8')})
                        except InvalidSignatureError:
                            cursor.close()
                            return 'Assinatura inválida do token.'                    
                    else:
                        cursor.close()
                        return 'Credenciais inválidas.'
                else:
                    cursor.close()
                    return 'Usuário não encontrado.'
            except Exception as err:
                return f'Erro ao fazer login: {err}'
            
            
        # CRIANDO AS METAS ===================================================================================================================================================
        @self.app.route('/metrics', methods=['POST'])
        def create_metrics():
            # Obtendo dados do formulário de METAS

            data = request.json
            id_user = 1
            metric_name = request.form.get('metric_name')
            unit_measurement = request.form.get('unit_measurement')

            #inserindo os dados na tabela METRICS
            try:
                cursor = self.connector.connection.cursor()
                query = ("INSERT INTO METRICS (USER_ID, METRIC_NAME, UNIT_MEASUREMENT) "
                         "VALUES (%s, %s, %s)")
                data = (id_user, metric_name, unit_measurement)
                cursor.execute(query, data)
                self.connector.connection.commit()
                cursor.close()
                resposta = {"metric_name": metric_name, "unit_measurement": unit_measurement}

                return jsonify(resposta)
            
            except Exception  as err:
                return f'Erro ao criar uma métrica: {err}'
        
        #INSERINDO O VALOR DAS DESPESAS =========================================================================================================================================

        @self.app.route('/add_metric_input', methods=['POST'])
        def add_metric_input():
            # Obtendo dados do formulário
            metric_id = request.form.get('metric_id')
            user_id = request.form.get('user_id')
            input_value = request.form.get('input_value')

            # Inserindo os dados na tabela METRICS_INPUT
            try:
                cursor = self.connector.connection.cursor()
                query = ("INSERT INTO METRICS_INPUT (METRIC_ID, USER_ID, INPUT_VALUE) "
                        "VALUES (%s, %s, %s)")
                data = (metric_id, user_id, input_value)
                cursor.execute(query, data)
                self.connector.connection.commit()
                cursor.close()
                
                # Consultando o nome da métrica com base no ID
                cursor = self.connector.connection.cursor()
                query = ("SELECT METRIC_NAME FROM METRICS WHERE ID = %s")
                cursor.execute(query, (metric_id,))
                metric_name = cursor.fetchone()[0]
                cursor.close()

                resposta = {
                    "metric_name": metric_name,
                    "input_value": input_value
                }

                return jsonify(resposta)

            except Exception as err:
                return f'Erro ao adicionar valor da métrica: {err}'

    def load(self):
        self.app.run(host=self.host, port=self.port)

    def encrypt_password(self, password):
        salt = bcrypt.gensalt()
        encrypted_password = bcrypt.hashpw(password.encode('utf-8'), salt)

        return encrypted_password
