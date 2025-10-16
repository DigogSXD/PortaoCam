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
