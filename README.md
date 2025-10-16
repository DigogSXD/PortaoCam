# Flask Tuya Smart Gate & Camera Controller

Este é um servidor web construído com **Flask** para controlar dispositivos inteligentes da plataforma **Tuya**, especificamente um portão/fechadura eletrônica e uma câmera de segurança.

O projeto oferece uma interface web simples para visualização da câmera e acionamento do portão, além de uma API RESTful segura (com autenticação JWT) para ser consumida por aplicativos móveis (como Flutter).

![Imagem de uma interface de controle de casa inteligente](https://storage.googleapis.com/gweb-uniblog-publish-prod/images/Google_Home_View_and_Control.width-1000.format-webp.webp)

## ✨ Funcionalidades

* **Interface Web Segura**:
    * Sistema de login e registro de usuários.
    * Visualização ao vivo da câmera (streaming via MJPEG).
    * Botão para acionar o portão (envia um pulso de comando).
* **API RESTful para Apps**:
    * Endpoints para registro, login, acionamento do portão e obtenção da URL da câmera.
    * Autenticação segura utilizando JSON Web Tokens (JWT).
* **Integração com Tuya**:
    * Utiliza a API oficial da Tuya para controle dos dispositivos.
    * Suporta tanto o modo de assinatura mais antigo (`openapi`) quanto o mais recente (`hmac`) para controle de dispositivos.
* **Gerenciamento de Usuários**:
    * Senhas armazenadas com hash seguro (Bcrypt).
    * Ferramentas de linha de comando (CLI) para criar, listar, deletar e atualizar usuários.
* **Banco de Dados**:
    * Utiliza SQLAlchemy para abstração do banco de dados, configurado para MySQL.

***

## 🛠️ Tecnologias Utilizadas

* **Backend**: Python 3, Flask
* **Banco de Dados**: MySQL, SQLAlchemy
* **Autenticação**: Flask-Bcrypt (hash de senhas), PyJWT (tokens para API)
* **Integração IoT**: `tuya-connector-python`
* **Streaming de Vídeo**: OpenCV
* **Configuração**: `python-dotenv` para variáveis de ambiente

***

## 🚀 Instalação e Configuração

Siga os passos abaixo para rodar o projeto localmente.

### 1. Pré-requisitos

* Python 3.8+
* Um servidor de banco de dados MySQL
* Credenciais da [Plataforma de Desenvolvedores Tuya IoT](https://developer.tuya.com/)

### 2. Clone o Repositório

```bash
git clone <url-do-seu-repositorio>
cd <nome-da-pasta>
```

### 3. Crie um Ambiente Virtual e Instale as Dependências

É uma boa prática usar um ambiente virtual para isolar as dependências do projeto.

# Crie o ambiente virtual
python -m venv venv

# Ative o ambiente (Windows)
.\venv\Scripts\activate

# Ative o ambiente (Linux/macOS)
source venv/bin/activate

# Crie um arquivo requirements.txt com o conteúdo abaixo e instale
pip install -r requirements.txt

### Exemplo env
# Chave secreta para o Flask (gere uma chave forte e aleatória)
# python -c 'import secrets; print(secrets.token_hex(16))'
SECRET_KEY="sua_chave_secreta_aqui"

# --- Configuração do Banco de Dados ---
DB_HOST="localhost"
DB_NAME="tuya_controller_db"
DB_USER="seu_usuario_db"
DB_PASSWORD="sua_senha_db"
DB_PORT="3306"

# --- Credenciais Tuya (Cloud Project API) ---
# Usadas para obter o stream da câmera
TUYA_ACCESS_ID="seu_access_id"
TUYA_ACCESS_KEY="seu_access_key"
TUYA_API_ENDPOINT="[https://openapi.tuyaus.com](https://openapi.tuyaus.com)" # Ou o endpoint da sua região

# --- Credenciais Tuya (HMAC Signature) ---
# Usadas para enviar comandos para o portão
TUYA_CLIENT_ID="seu_client_id"
TUYA_CLIENT_SECRET="seu_client_secret"
TUYA_REGION="openapi.tuyaus.com" # Ou a região do seu datacenter

# --- IDs e Códigos dos Dispositivos ---
TUYA_DEVICE_ID_CAMERA="id_do_dispositivo_da_camera"
TUYA_DEVICE_ID_GATE="id_do_dispositivo_do_portao"
TUYA_CODE="switch_1" # Código do comando para o relé/portão (ex: switch_1)
PULSE_MS=800 # Duração do pulso em milissegundos

